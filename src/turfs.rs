pub mod processing;

#[cfg(feature = "monstermos")]
pub mod monstermos;

#[cfg(feature = "putnamos")]
pub mod putnamos;

#[cfg(feature = "katmos")]
pub mod katmos;

use crate::gas::Mixture;

use auxtools::*;

use crate::constants::*;

use crate::GasArena;

use dashmap::DashMap;

use fxhash::FxBuildHasher;

use rayon;

use rayon::prelude::*;

use std::mem::drop;

use crate::callbacks::aux_callbacks_sender;

use crossbeam_utils::sync::{ShardedLock, ShardedLockReadGuard, ShardedLockWriteGuard};
use petgraph::graphmap::DiGraphMap;

const NORTH: u8 = 1;
const SOUTH: u8 = 2;
const EAST: u8 = 4;
const WEST: u8 = 8;
const UP: u8 = 16;
const DOWN: u8 = 32;

const fn adj_flag_to_idx(adj_flag: u8) -> usize {
	match adj_flag {
		NORTH => 0,
		SOUTH => 1,
		EAST => 2,
		WEST => 3,
		UP => 4,
		DOWN => 5,
		_ => 6,
	}
}

pub const NONE: u8 = 0;
pub const SIMULATION_DIFFUSE: u8 = 1;
pub const SIMULATION_ALL: u8 = 2;
pub const SIMULATION_ANY: u8 = SIMULATION_DIFFUSE | SIMULATION_ALL;
pub const SIMULATION_DISABLED: u8 = 4;
pub const SIMULATION_FLAGS: u8 = SIMULATION_ANY | SIMULATION_DISABLED;

type TurfID = u32;

// TurfMixture can be treated as "immutable" for all intents and purposes--put other data somewhere else
#[derive(Clone, Copy, Default, Hash, Eq, PartialEq)]
struct TurfMixture {
	pub mix: usize,
	pub flags: u8,
	pub planetary_atmos: Option<u32>,
}

#[allow(dead_code)]
impl TurfMixture {
	pub fn enabled(&self) -> bool {
		let simul_flags = self.flags & SIMULATION_FLAGS;
		simul_flags & SIMULATION_DISABLED == 0 && simul_flags & SIMULATION_ANY != 0
	}
	pub fn adjacent_mixes<'a>(
		&'a self,
		all_mixtures: &'a [parking_lot::RwLock<Mixture>],
		this_idx: TurfID,
		graph: &'a ShardedLockReadGuard<DiGraphMap<TurfID, u8>>,
	) -> impl Iterator<Item = &'a parking_lot::RwLock<Mixture>> {
		graph
			.neighbors_directed(this_idx, petgraph::Outgoing)
			.filter_map(move |idx| {
				let mixnum = turf_gases().get(&idx)?.mix;
				all_mixtures.get(mixnum)
			})
	}
	pub fn adjacent_mixes_with_adj_info<'a>(
		&'a self,
		all_mixtures: &'a [parking_lot::RwLock<Mixture>],
		this_idx: TurfID,
		graph: &'a ShardedLockReadGuard<DiGraphMap<TurfID, u8>>,
	) -> impl Iterator<Item = (usize, TurfID, &'a parking_lot::RwLock<Mixture>)> {
		graph
			.neighbors_directed(this_idx, petgraph::Outgoing)
			.enumerate()
			.filter_map(move |(ctr, idx)| {
				let mixnum = turf_gases().get(&idx)?.mix;
				all_mixtures.get(mixnum).map(|mix| (ctr, idx, mix))
			})

		/*
		self.adjacents
			.iter()
			.enumerate()
			.filter_map(move |(i, idx)| {
				idx.and_then(|id| all_mixtures.get(id.get()))
					.map(|g| (i, adjacent_tile_id(i as u8, this_idx, max_x, max_y), g))
			})
		*/
	}
	pub fn is_immutable(&self) -> bool {
		GasArena::with_all_mixtures(|all_mixtures| {
			all_mixtures
				.get(self.mix)
				.unwrap_or_else(|| panic!("Gas mixture not found for turf: {}", self.mix))
				.read()
				.is_immutable()
		})
	}
	pub fn return_pressure(&self) -> f32 {
		GasArena::with_all_mixtures(|all_mixtures| {
			all_mixtures
				.get(self.mix)
				.unwrap_or_else(|| panic!("Gas mixture not found for turf: {}", self.mix))
				.read()
				.return_pressure()
		})
	}
	pub fn total_moles(&self) -> f32 {
		GasArena::with_all_mixtures(|all_mixtures| {
			all_mixtures
				.get(self.mix)
				.unwrap_or_else(|| panic!("Gas mixture not found for turf: {}", self.mix))
				.read()
				.total_moles()
		})
	}
	pub fn clear_air(&self) {
		GasArena::with_all_mixtures(|all_mixtures| {
			all_mixtures
				.get(self.mix)
				.unwrap_or_else(|| panic!("Gas mixture not found for turf: {}", self.mix))
				.write()
				.clear();
		});
	}
	pub fn clear_vol(&self, amt: f32) {
		GasArena::with_all_mixtures(|all_mixtures| {
			let moles = all_mixtures
				.get(self.mix)
				.unwrap_or_else(|| panic!("Gas mixture not found for turf: {}", self.mix))
				.read()
				.total_moles();
			if amt >= moles {
				all_mixtures
					.get(self.mix)
					.unwrap_or_else(|| panic!("Gas mixture not found for turf: {}", self.mix))
					.write()
					.clear();
			} else {
				drop(
					all_mixtures
						.get(self.mix)
						.unwrap_or_else(|| panic!("Gas mixture not found for turf: {}", self.mix))
						.write()
						.remove(amt),
				);
			}
		});
	}
	pub fn get_gas_copy(&self) -> Mixture {
		let mut ret: Mixture = Mixture::new();
		GasArena::with_all_mixtures(|all_mixtures| {
			let to_copy = all_mixtures
				.get(self.mix)
				.unwrap_or_else(|| panic!("Gas mixture not found for turf: {}", self.mix))
				.read();
			ret.copy_from_mutable(&to_copy);
			ret.volume = to_copy.volume;
		});
		ret
	}
}

// all non-space turfs get these, not just ones with air--a lot of gas logic relies on all TurfMixtures having a valid mix
#[derive(Clone, Copy, Default)]
struct ThermalInfo {
	pub temperature: f32,
	pub thermal_conductivity: f32,
	pub heat_capacity: f32,
	pub adjacency: u8,
	pub adjacent_to_space: bool,
}
lazy_static::lazy_static! {
	// Adjacencies infos, nodes are TurfIDs, edges are direction flags
	static ref TURF_ADJACENCIES: ShardedLock<DiGraphMap<TurfID, u8>> = ShardedLock::new(DiGraphMap::new());
	// All the turfs that have gas mixtures.
	static ref TURF_GASES: DashMap<TurfID, TurfMixture, FxBuildHasher> = DashMap::with_hasher(FxBuildHasher::default());
	// Turfs with temperatures/heat capacities. This is distinct from the above.
	static ref TURF_TEMPERATURES: DashMap<TurfID, ThermalInfo, FxBuildHasher> = DashMap::with_hasher(FxBuildHasher::default());
	// We store planetary atmos by hash of the initial atmos string here for speed.
	static ref PLANETARY_ATMOS: DashMap<u32, Mixture, FxBuildHasher> = DashMap::with_hasher(FxBuildHasher::default());
}

#[shutdown]
fn _shutdown_turfs() {
	with_adjacency_write(|mut graph| graph.clear());
	TURF_GASES.clear();
	TURF_TEMPERATURES.clear();
	PLANETARY_ATMOS.clear();
}

pub fn with_adjacency_read<T, F>(f: F) -> T
where
	F: FnOnce(ShardedLockReadGuard<DiGraphMap<TurfID, u8>>) -> T,
{
	f(TURF_ADJACENCIES.read().unwrap())
}

pub fn with_adjacency_write<T, F>(f: F) -> T
where
	F: FnOnce(ShardedLockWriteGuard<DiGraphMap<TurfID, u8>>) -> T,
{
	f(TURF_ADJACENCIES.write().unwrap())
}

// this would lead to undefined info if it were possible for something to put a None on it during operation, but nothing's going to do that
fn turf_gases() -> &'static DashMap<TurfID, TurfMixture, FxBuildHasher> {
	&TURF_GASES
}

fn planetary_atmos() -> &'static DashMap<u32, Mixture, FxBuildHasher> {
	&PLANETARY_ATMOS
}

fn turf_temperatures() -> &'static DashMap<TurfID, ThermalInfo, FxBuildHasher> {
	&TURF_TEMPERATURES
}

#[hook("/turf/proc/update_air_ref")]
fn _hook_register_turf() {
	let simulation_level = args[0].as_number().map_err(|_| {
		runtime!(
			"Attempt to interpret non-number value as number {} {}:{}",
			std::file!(),
			std::line!(),
			std::column!()
		)
	})?;
	let sender = aux_callbacks_sender(crate::callbacks::TURFS);
	if simulation_level < 0.0 {
		let id = unsafe { src.raw.data.id };
		drop(sender.send(Box::new(move || {
			turf_gases().remove(&id);
			Ok(Value::null())
		})));
		Ok(Value::null())
	} else {
		let mut to_insert: TurfMixture = TurfMixture::default();
		let air = src.get(byond_string!("air"))?;
		to_insert.mix = air
			.get_number(byond_string!("_extools_pointer_gasmixture"))
			.map_err(|_| {
				runtime!(
					"Attempt to interpret non-number value as number {} {}:{}",
					std::file!(),
					std::line!(),
					std::column!()
				)
			})?
			.to_bits() as usize;
		to_insert.flags = args[0].as_number().map_err(|_| {
			runtime!(
				"Attempt to interpret non-number value as number {} {}:{}",
				std::file!(),
				std::line!(),
				std::column!()
			)
		})? as u8;
		if let Ok(is_planet) = src.get_number(byond_string!("planetary_atmos")) {
			if is_planet != 0.0 {
				if let Ok(at_str) = src.get_string(byond_string!("initial_gas_mix")) {
					to_insert.planetary_atmos = Some(fxhash::hash32(&at_str));
					let mut entry = planetary_atmos()
						.entry(to_insert.planetary_atmos.unwrap())
						.or_insert_with(|| {
							let mut gas = to_insert.get_gas_copy();
							gas.mark_immutable();
							gas
						});
					entry.mark_immutable();
				}
			}
		}
		let id = unsafe { src.raw.data.id };
		drop(sender.send(Box::new(move || {
			turf_gases().insert(id, to_insert);
			Ok(Value::null())
		})));
		Ok(Value::null())
	}
}

#[hook("/turf/proc/__auxtools_update_turf_temp_info")]
fn _hook_turf_update_temp() {
	let sender = aux_callbacks_sender(crate::callbacks::TEMPERATURE);
	let id = unsafe { src.raw.data.id };
	if src
		.get_number(byond_string!("thermal_conductivity"))
		.unwrap_or_default()
		> 0.0 && src
		.get_number(byond_string!("heat_capacity"))
		.unwrap_or_default()
		> 0.0
	{
		let mut to_insert = ThermalInfo {
			temperature: 293.15,
			thermal_conductivity: 0.0,
			heat_capacity: 0.0,
			adjacency: NORTH | SOUTH | WEST | EAST,
			adjacent_to_space: false,
		};
		to_insert.thermal_conductivity = src
			.get_number(byond_string!("thermal_conductivity"))
			.map_err(|_| {
				runtime!(
					"Attempt to interpret non-number value as number {} {}:{}",
					std::file!(),
					std::line!(),
					std::column!()
				)
			})?;
		to_insert.heat_capacity = src
			.get_number(byond_string!("heat_capacity"))
			.map_err(|_| {
				runtime!(
					"Attempt to interpret non-number value as number {} {}:{}",
					std::file!(),
					std::line!(),
					std::column!()
				)
			})?;
		to_insert.adjacency = NORTH | SOUTH | WEST | EAST;
		to_insert.adjacent_to_space = args[0].as_number().map_err(|_| {
			runtime!(
				"Attempt to interpret non-number value as number {} {}:{}",
				std::file!(),
				std::line!(),
				std::column!()
			)
		})? != 0.0;
		to_insert.temperature = src
			.get_number(byond_string!("initial_temperature"))
			.map_err(|_| {
				runtime!(
					"Attempt to interpret non-number value as number {} {}:{}",
					std::file!(),
					std::line!(),
					std::column!()
				)
			})?;
		drop(sender.send(Box::new(move || {
			turf_temperatures().insert(id, to_insert);
			Ok(Value::null())
		})));
	} else {
		drop(sender.send(Box::new(move || {
			turf_temperatures().remove(&id);
			Ok(Value::null())
		})));
	}
	Ok(Value::null())
}

#[hook("/turf/proc/set_sleeping")]
fn _hook_sleep() {
	let arg = if let Some(arg_get) = args.get(0) {
		// null is falsey in byond so
		arg_get.as_number().map_err(|_| {
			runtime!(
				"Attempt to interpret non-number value as number {} {}:{}",
				std::file!(),
				std::line!(),
				std::column!()
			)
		})?
	} else {
		0.0
	};
	let src_id = unsafe { src.raw.data.id };
	if arg == 0.0 {
		turf_gases().entry(src_id).and_modify(|turf| {
			turf.flags &= !SIMULATION_DISABLED;
		});
	} else {
		turf_gases().entry(src_id).and_modify(|turf| {
			turf.flags |= SIMULATION_DISABLED;
		});
	}
	Ok(Value::from(true))
}
#[hook("/turf/proc/__update_auxtools_turf_adjacency_info")]
fn _hook_infos(arg0: Value, arg1: Value) {
	let update_now = arg1.as_number().unwrap_or(0.0) != 0.0;
	let adjacent_to_spess = arg0.as_number().unwrap_or(0.0) != 0.0;
	let id = unsafe { src.raw.data.id };
	let sender = aux_callbacks_sender(crate::callbacks::ADJACENCIES);
	let boxed_fn: Box<dyn Fn() -> DMResult + Send + Sync> = Box::new(move || {
		let src_turf = unsafe { Value::turf_by_id_unchecked(id) };
		if let Ok(adjacent_list) = src_turf.get_list(byond_string!("atmos_adjacent_turfs")) {
			with_adjacency_write(|mut graph| -> DMResult {
				//Can't just fucking remove it because mut borrows and borrows don't mix
				let old_neighbors = graph
					.neighbors_directed(id, petgraph::Outgoing)
					.collect::<Vec<_>>();
				old_neighbors.into_iter().for_each(|other| {
					graph.remove_edge(id, other);
				});
				for i in 1..=adjacent_list.len() {
					let adj_val = adjacent_list.get(i)?;
					let adjacent_num = adjacent_list.get(&adj_val)?.as_number()? as u8;
					graph.add_edge(id, unsafe { adj_val.raw.data.id }, adjacent_num);
				}
				Ok(Value::null())
			})?;
		} else {
			with_adjacency_write(|mut graph| graph.remove_node(id));
		}
		if let Ok(blocks_air) = src_turf.get_number(byond_string!("blocks_air")) {
			if blocks_air == 0.0 {
				turf_gases().entry(id).and_modify(|turf| {
					turf.flags &= !SIMULATION_DISABLED;
				});
			} else {
				turf_gases().entry(id).and_modify(|turf| {
					turf.flags |= SIMULATION_DISABLED;
				});
			}
		}
		if let Ok(atmos_blocked_directions) =
			src_turf.get_number(byond_string!("conductivity_blocked_directions"))
		{
			let adjacency = NORTH | SOUTH | WEST | EAST & !(atmos_blocked_directions as u8);
			turf_temperatures()
				.entry(id)
				.and_modify(|entry| {
					entry.adjacency = adjacency;
				})
				.or_insert_with(|| ThermalInfo {
					temperature: src_turf
						.get_number(byond_string!("initial_temperature"))
						.unwrap_or(TCMB),
					thermal_conductivity: src_turf
						.get_number(byond_string!("thermal_conductivity"))
						.unwrap_or(0.0),
					heat_capacity: src_turf
						.get_number(byond_string!("heat_capacity"))
						.unwrap_or(0.0),
					adjacency,
					adjacent_to_space: adjacent_to_spess,
				});
		}
		Ok(Value::null())
	});
	if update_now {
		boxed_fn()?;
	} else {
		drop(sender.send(boxed_fn));
	}
	Ok(Value::null())
}

#[hook("/turf/proc/return_temperature")]
fn _hook_turf_temperature() {
	if let Some(temp_info) = turf_temperatures().get(&unsafe { src.raw.data.id }) {
		if temp_info.temperature.is_normal() {
			Ok(Value::from(temp_info.temperature))
		} else {
			src.get(byond_string!("initial_temperature"))
		}
	} else {
		src.get(byond_string!("initial_temperature"))
	}
}

// gas_overlays: list( GAS_ID = list( VIS_FACTORS = OVERLAYS )) got it? I don't
/// Updates the visual overlays for the given turf.
/// Will use a cached overlay list if one exists.
/// # Errors
/// If auxgm wasn't implemented properly or there's an invalid gas mixture.
pub fn update_visuals(src: Value) -> DMResult {
	use super::gas;
	match src.get(byond_string!("air")) {
		Err(_) => Ok(Value::null()),
		Ok(air) => {
			let overlay_types = List::new();
			let gas_overlays = Value::globals()
				.get(byond_string!("gas_data"))?
				.get_list(byond_string!("overlays"))?;
			let ptr = air
				.get_number(byond_string!("_extools_pointer_gasmixture"))
				.map_err(|_| {
					runtime!(
						"Attempt to interpret non-number value as number {} {}:{}",
						std::file!(),
						std::line!(),
						std::column!()
					)
				})?
				.to_bits() as usize;
			GasArena::with_gas_mixture(ptr, |mix| {
				mix.for_each_gas(|idx, moles| {
					if let Some(amt) = gas::types::gas_visibility(idx) {
						if moles > amt {
							let this_overlay_list =
								gas_overlays.get(gas::gas_idx_to_id(idx)?)?.as_list()?;
							if let Ok(this_gas_overlay) = this_overlay_list.get(
								(moles / MOLES_GAS_VISIBLE_STEP)
									.ceil()
									.min(FACTOR_GAS_VISIBLE_MAX)
									.max(1.0) as u32,
							) {
								overlay_types.append(this_gas_overlay);
							}
						}
					}
					Ok(())
				})
			})?;

			src.call("set_visuals", &[&Value::from(overlay_types)])
		}
	}
}

fn adjacent_tile_id(id: u8, i: TurfID, max_x: i32, max_y: i32) -> TurfID {
	let z_size = max_x * max_y;
	let i = i as i32;
	match id {
		0 => (i + max_x) as TurfID,
		1 => (i - max_x) as TurfID,
		2 => (i + 1) as TurfID,
		3 => (i - 1) as TurfID,
		4 => (i + z_size) as TurfID,
		5 => (i - z_size) as TurfID,
		_ => i as TurfID,
	}
}
#[derive(Clone, Copy)]
struct AdjacentTileIDs {
	adj: u8,
	i: TurfID,
	max_x: i32,
	max_y: i32,
	count: u8,
}

impl Iterator for AdjacentTileIDs {
	type Item = (u8, TurfID);

	fn next(&mut self) -> Option<Self::Item> {
		loop {
			if self.count > 6 {
				return None;
			}
			self.count += 1;
			let bit = 1 << (self.count - 1);
			if self.adj & bit == bit {
				return Some((
					self.count - 1,
					adjacent_tile_id(self.count - 1, self.i, self.max_x, self.max_y),
				));
			}
		}
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		(0, Some(self.adj.count_ones() as usize))
	}
}

use std::iter::FusedIterator;

impl FusedIterator for AdjacentTileIDs {}

fn adjacent_tile_ids(adj: u8, i: TurfID, max_x: i32, max_y: i32) -> AdjacentTileIDs {
	AdjacentTileIDs {
		adj,
		i,
		max_x,
		max_y,
		count: 0,
	}
}
