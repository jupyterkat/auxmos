//Monstermos, but zoned, and multithreaded!

use super::*;

use std::{
	cell::Cell,
	{
		collections::{HashMap, HashSet},
		sync::atomic::AtomicUsize,
	},
};

use indexmap::{IndexMap, IndexSet};

use ahash::RandomState;
use fxhash::FxBuildHasher;

use crate::callbacks::process_aux_callbacks;

use auxcallback::byond_callback_sender;

use dashmap::DashMap;

type MixWithID = (TurfID, TurfMixture);

type RefMixWithID<'a> = (&'a TurfID, &'a TurfMixture);

#[derive(Copy, Clone)]
struct MonstermosInfo {
	mole_delta: f32,
	curr_transfer_amount: f32,
	curr_transfer_dir: Option<TurfID>,
	fast_done: bool,
}

impl Default for MonstermosInfo {
	fn default() -> MonstermosInfo {
		MonstermosInfo {
			mole_delta: 0_f32,
			curr_transfer_amount: 0_f32,
			curr_transfer_dir: None,
			fast_done: false,
		}
	}
}

#[derive(Copy, Clone)]
struct ReducedInfo {
	curr_transfer_amount: f32,
	curr_transfer_dir: Option<TurfID>,
}

impl Default for ReducedInfo {
	fn default() -> ReducedInfo {
		ReducedInfo {
			curr_transfer_amount: 0_f32,
			curr_transfer_dir: None,
		}
	}
}

/*
impl MonstermosInfo {
	fn adjust_eq_movement(&mut self, adjacent: Option<&mut Self>, amount: f32) {
		self.transfer_dirs[dir_index] += amount;
		if let Some(adj) = adjacent {
			if dir_index != 6 {
				adj.transfer_dirs[OPP_DIR_INDEX[dir_index]] -= amount;
			}
		}
	}
}
*/

fn adjust_eq_movement(
	this_turf: Option<TurfID>,
	that_turf: Option<TurfID>,
	amount: f32,
	graph: &mut DiGraphMap<Option<TurfID>, f32>,
) {
	if graph.contains_edge(this_turf, that_turf) {
		*graph.edge_weight_mut(this_turf, that_turf).unwrap() += amount;
	} else {
		graph.add_edge(this_turf, that_turf, amount);
	}
	if that_turf.is_some() {
		if graph.contains_edge(that_turf, this_turf) {
			*graph.edge_weight_mut(that_turf, this_turf).unwrap() -= amount;
		} else {
			graph.add_edge(that_turf, this_turf, -amount);
		}
	}
}

fn finalize_eq(
	i: TurfID,
	turf: &TurfMixture,
	turfs: &IndexMap<TurfID, TurfMixture, FxBuildHasher>,
	info: &DashMap<TurfID, MonstermosInfo, FxBuildHasher>,
	eq_movement_graph: &mut DiGraphMap<Option<TurfID>, f32>,
) {
	let sender = byond_callback_sender();
	let transfer_dirs = {
		let pairs = eq_movement_graph
			.edges_directed(Some(i), petgraph::Outgoing)
			.map(|(_, opt2, amt)| (opt2, *amt))
			.collect::<HashMap<_, _, FxBuildHasher>>();

		if pairs.is_empty() {
			return;
		}

		pairs.iter().for_each(|(that_node, _)| {
			eq_movement_graph.remove_edge(Some(i), *that_node);
		});
		/*
		let transfer_dirs = monstermos_orig.transfer_dirs;
		monstermos_orig
			.transfer_dirs
			.iter_mut()
			.for_each(|a| *a = 0.0); // null it out to prevent infinite recursion.
		*/
		pairs
	};
	if let Some(&planet_transfer_amount) = transfer_dirs.get(&None) {
		if planet_transfer_amount > 0.0 {
			if turf.total_moles() < planet_transfer_amount {
				finalize_eq_neighbors(turf, turfs, &transfer_dirs, info, eq_movement_graph);
			}
			drop(GasArena::with_gas_mixture_mut(turf.mix, |gas| {
				gas.add(-planet_transfer_amount);
				Ok(())
			}));
		} else if planet_transfer_amount < 0.0 {
			if let Some(air_entry) = turf
				.planetary_atmos
				.and_then(|i| planetary_atmos().try_get(&i).try_unwrap())
			{
				let planet_air = air_entry.value();
				let planet_sum = planet_air.total_moles();
				if planet_sum > 0.0 {
					drop(GasArena::with_gas_mixture_mut(turf.mix, |gas| {
						gas.merge(&(planet_air * (-planet_transfer_amount / planet_sum)));
						Ok(())
					}));
				}
			}
		}
	}
	with_adjacency_read(|graph| {
		for (_, _, &adj_turf) in graph.edges_directed(turf.mix, petgraph::Outgoing) {
			let amount = *transfer_dirs.get(&Some(adj_turf)).unwrap_or(&0.0);
			if amount > 0.0 {
				if turf.total_moles() < amount {
					finalize_eq_neighbors(turf, turfs, &transfer_dirs, info, eq_movement_graph);
				}
				if let Some(adj_tmix) = turfs.get(&adj_turf) {
					eq_movement_graph
						.edge_weight_mut(Some(adj_turf), Some(i))
						.and_then(|amt| {
							*amt = 0.0;
							Some(())
						});
					if turf.mix != adj_tmix.mix {
						drop(GasArena::with_gas_mixtures_mut(
							turf.mix,
							adj_tmix.mix,
							|air, other_air| {
								other_air.merge(&air.remove(amount));
								Ok(())
							},
						));
					}
					drop(sender.try_send(Box::new(move || {
						let real_amount = Value::from(amount);
						let turf = unsafe { Value::turf_by_id_unchecked(i as u32) };
						let other_turf = unsafe { Value::turf_by_id_unchecked(adj_turf as u32) };
						if let Err(e) =
							turf.call("consider_pressure_difference", &[&other_turf, &real_amount])
						{
							Proc::find(byond_string!("/proc/stack_trace"))
								.ok_or_else(|| runtime!("Couldn't find stack_trace!"))?
								.call(&[&Value::from_string(e.message.as_str())?])?;
						}
						Ok(Value::null())
					})));
				}
			}
		}
	});
}

fn finalize_eq_neighbors(
	m: &TurfMixture,
	turfs: &IndexMap<TurfID, TurfMixture, FxBuildHasher>,
	transfer_dirs: &HashMap<Option<TurfID>, f32, FxBuildHasher>,
	info: &DashMap<TurfID, MonstermosInfo, FxBuildHasher>,
	eq_movement_graph: &mut DiGraphMap<Option<TurfID>, f32>,
) {
	with_adjacency_read(|graph| {
		for (_, _, &adj_turf) in graph.edges_directed(m.mix, petgraph::Outgoing) {
			let amount = *transfer_dirs.get(&Some(adj_turf)).unwrap_or(&0.0);
			if amount < 0.0 {
				let other_turf = {
					let maybe = turfs.get(&adj_turf);
					if maybe.is_none() {
						continue;
					}
					maybe.unwrap()
				};
				finalize_eq(adj_turf, other_turf, turfs, info, eq_movement_graph);
			}
		}
	});
}

fn monstermos_fast_process(
	i: TurfID,
	m: &TurfMixture,
	turfs: &IndexMap<TurfID, TurfMixture, FxBuildHasher>,
	info: &DashMap<TurfID, MonstermosInfo, FxBuildHasher>,
	eq_movement_graph: &mut DiGraphMap<Option<TurfID>, f32>,
) {
	let mut cur_info = {
		let maybe_cur_orig = info.get_mut(&i);
		if maybe_cur_orig.is_none() {
			return;
		}
		let mut cur_info = maybe_cur_orig.unwrap();
		cur_info.fast_done = true;
		*cur_info
	};
	let mut eligible_adjacents: Vec<usize> = Default::default();
	if cur_info.mole_delta > 0.0 {
		with_adjacency_read(|graph| {
			for (_, adj_mix, &adj_turf) in graph.edges_directed(m.mix, petgraph::Outgoing) {
				if turfs.get(&adj_turf).map_or(false, TurfMixture::enabled) {
					if let Some(adj_info) = info.get(&adj_turf) {
						if !adj_info.fast_done {
							eligible_adjacents.push(adj_mix);
						}
					}
				}
			}
			if eligible_adjacents.is_empty() {
				info.entry(i).and_modify(|entry| *entry = cur_info);
				return;
			}
			let moles_to_move = cur_info.mole_delta / eligible_adjacents.len() as f32;
			eligible_adjacents.into_iter().for_each(|item| {
				graph.edge_weight(m.mix, item).and_then(|&idx| {
					if let Some(mut adj_info) = info.get_mut(&idx) {
						adjust_eq_movement(Some(i), Some(idx), moles_to_move, eq_movement_graph);
						cur_info.mole_delta -= moles_to_move;
						adj_info.mole_delta += moles_to_move;
					}
					info.entry(i).and_modify(|entry| *entry = cur_info);
					Some(())
				});
			});
		});
	}
}

fn give_to_takers(
	giver_turfs: &[RefMixWithID],
	_taker_turfs: &[RefMixWithID],
	turfs: &IndexMap<TurfID, TurfMixture, FxBuildHasher>,
	info: &DashMap<TurfID, MonstermosInfo, FxBuildHasher>,
	eq_movement_graph: &mut DiGraphMap<Option<TurfID>, f32>,
) {
	let mut queue: IndexMap<TurfID, &TurfMixture, FxBuildHasher> =
		IndexMap::with_hasher(FxBuildHasher::default());
	with_adjacency_read(|graph| {
		for &(i, m) in giver_turfs {
			let mut giver_info = {
				let maybe_giver_orig = info.get_mut(i);
				if maybe_giver_orig.is_none() {
					continue;
				}
				let mut giver_info = maybe_giver_orig.unwrap();
				giver_info.curr_transfer_dir = None;
				giver_info.curr_transfer_amount = 0.0;
				*giver_info
			};
			queue.insert(*i, m);
			let mut queue_idx = 0;

			while let Some((&idx, _)) = queue.get_index(queue_idx) {
				if giver_info.mole_delta <= 0.0 {
					break;
				}
				for (_, _, &adj_idx) in graph.edges_directed(m.mix, petgraph::Outgoing) {
					if giver_info.mole_delta <= 0.0 {
						break;
					}
					if let Some(mut adj_info) = info.get_mut(&adj_idx) {
						if let Some(adj_mix) = turfs
							.get(&adj_idx)
							.and_then(|terf| terf.enabled().then(|| terf))
						{
							if queue.insert(adj_idx, adj_mix).is_none() {
								adj_info.curr_transfer_dir = Some(idx);
								adj_info.curr_transfer_amount = 0.0;
								if adj_info.mole_delta < 0.0 {
									// this turf needs gas. Let's give it to 'em.
									if -adj_info.mole_delta > giver_info.mole_delta {
										// we don't have enough gas
										adj_info.curr_transfer_amount -= giver_info.mole_delta;
										adj_info.mole_delta += giver_info.mole_delta;
										giver_info.mole_delta = 0.0;
									} else {
										// we have enough gas.
										adj_info.curr_transfer_amount += adj_info.mole_delta;
										giver_info.mole_delta += adj_info.mole_delta;
										adj_info.mole_delta = 0.0;
									}
								}
							}
						}
					}
					info.entry(*i).and_modify(|entry| *entry = giver_info);
				}

				queue_idx += 1;
			}

			for (idx, _) in queue.drain(..).rev() {
				if let Some(mut turf_info) = info.get_mut(&idx) {
					if turf_info.curr_transfer_amount != 0.0
						&& turf_info.curr_transfer_dir.is_some()
					{
						if let Some(mut adj_info) =
							info.get_mut(&turf_info.curr_transfer_dir.unwrap())
						{
							adjust_eq_movement(
								Some(idx),
								turf_info.curr_transfer_dir,
								turf_info.curr_transfer_amount,
								eq_movement_graph,
							);
							adj_info.curr_transfer_amount += turf_info.curr_transfer_amount;
							turf_info.curr_transfer_amount = 0.0;
						}
					}
				}
			}
		}
	});
}

fn take_from_givers(
	taker_turfs: &[RefMixWithID],
	_giver_turfs: &[RefMixWithID],
	turfs: &IndexMap<TurfID, TurfMixture, FxBuildHasher>,
	info: &DashMap<TurfID, MonstermosInfo, FxBuildHasher>,
	eq_movement_graph: &mut DiGraphMap<Option<TurfID>, f32>,
) {
	let mut queue: IndexMap<TurfID, &TurfMixture, FxBuildHasher> =
		IndexMap::with_hasher(FxBuildHasher::default());

	with_adjacency_read(|graph| {
		for &(i, m) in taker_turfs {
			let mut taker_info = {
				let maybe_taker_orig = info.get_mut(i);
				if maybe_taker_orig.is_none() {
					continue;
				}
				let mut taker_info = maybe_taker_orig.unwrap();
				taker_info.curr_transfer_dir = None;
				taker_info.curr_transfer_amount = 0.0;
				*taker_info
			};
			queue.insert(*i, m);
			let mut queue_idx = 0;
			while let Some((&idx, _)) = queue.get_index(queue_idx) {
				if taker_info.mole_delta >= 0.0 {
					break;
				}
				for (_, _, &adj_idx) in graph.edges_directed(m.mix, petgraph::Outgoing) {
					if taker_info.mole_delta >= 0.0 {
						break;
					}
					if let Some(mut adj_info) = info.get_mut(&adj_idx) {
						if let Some(adj_mix) = turfs
							.get(&adj_idx)
							.and_then(|terf| terf.enabled().then(|| terf))
						{
							if queue.insert(adj_idx, adj_mix).is_none() {
								adj_info.curr_transfer_dir = Some(idx);
								adj_info.curr_transfer_amount = 0.0;
								if adj_info.mole_delta > 0.0 {
									// this turf has gas we can succ. Time to succ.
									if adj_info.mole_delta > -taker_info.mole_delta {
										// they have enough gase
										adj_info.curr_transfer_amount -= taker_info.mole_delta;
										adj_info.mole_delta += taker_info.mole_delta;
										taker_info.mole_delta = 0.0;
									} else {
										// they don't have neough gas
										adj_info.curr_transfer_amount += adj_info.mole_delta;
										taker_info.mole_delta += adj_info.mole_delta;
										adj_info.mole_delta = 0.0;
									}
								}
							}
						}
					}
					info.entry(*i).and_modify(|entry| *entry = taker_info);
				}
				queue_idx += 1;
			}
			for (idx, _) in queue.drain(..).rev() {
				if let Some(mut turf_info) = info.get_mut(&idx) {
					if turf_info.curr_transfer_amount != 0.0
						&& turf_info.curr_transfer_dir.is_some()
					{
						if let Some(mut adj_info) =
							info.get_mut(&turf_info.curr_transfer_dir.unwrap())
						{
							adjust_eq_movement(
								Some(idx),
								turf_info.curr_transfer_dir,
								turf_info.curr_transfer_amount,
								eq_movement_graph,
							);
							adj_info.curr_transfer_amount += turf_info.curr_transfer_amount;
							turf_info.curr_transfer_amount = 0.0;
						}
					}
				}
			}
		}
	});
}

fn explosively_depressurize(turf_idx: TurfID, equalize_hard_turf_limit: usize) -> DMResult {
	let mut info: HashMap<TurfID, Cell<ReducedInfo>, FxBuildHasher> =
		HashMap::with_hasher(FxBuildHasher::default());
	let mut turfs: IndexSet<TurfID, FxBuildHasher> =
		IndexSet::with_hasher(FxBuildHasher::default());
	let mut progression_order: IndexSet<MixWithID, RandomState> =
		IndexSet::with_hasher(RandomState::default());
	let mut space_turfs: IndexSet<TurfID, FxBuildHasher> =
		IndexSet::with_hasher(FxBuildHasher::default());
	turfs.insert(turf_idx);
	let mut warned_about_planet_atmos = false;
	let mut cur_queue_idx = 0;
	with_adjacency_read(|graph| -> DMResult {
		while cur_queue_idx < turfs.len() {
			let i = turfs[cur_queue_idx];
			cur_queue_idx += 1;
			let m = {
				let maybe = turf_gases().get(&i);
				if maybe.is_none() {
					continue;
				}
				*maybe.unwrap()
			};
			if m.planetary_atmos.is_some() {
				warned_about_planet_atmos = true;
				continue;
			}
			if m.is_immutable() {
				if space_turfs.insert(i) {
					unsafe { Value::turf_by_id_unchecked(i) }
						.set(byond_string!("pressure_specific_target"), &unsafe {
							Value::turf_by_id_unchecked(i)
						})?;
				}
			} else {
				if cur_queue_idx > equalize_hard_turf_limit {
					continue;
				}
				for (_, _, &loc) in graph.edges_directed(m.mix, petgraph::Outgoing) {
					let insert_success = {
						if turf_gases().get(&loc).is_some() {
							turfs.insert(loc)
						} else {
							false
						}
					};
					if insert_success {
						unsafe { Value::turf_by_id_unchecked(i) }.call(
							"consider_firelocks",
							&[&unsafe { Value::turf_by_id_unchecked(loc) }],
						)?;
					}
				}
			}
			if warned_about_planet_atmos {
				break;
			}
		}
		Ok(Value::null())
	})?;

	if warned_about_planet_atmos {
		return Ok(Value::null()); // planet atmos > space
	}

	process_aux_callbacks(crate::callbacks::TURFS);
	process_aux_callbacks(crate::callbacks::ADJACENCIES);

	if space_turfs.is_empty() {
		return Ok(Value::null());
	}

	for i in space_turfs.iter() {
		let maybe_turf = turf_gases().get(i);
		if maybe_turf.is_none() {
			continue;
		}
		let m = *maybe_turf.unwrap();
		progression_order.insert((*i, m));
	}

	cur_queue_idx = 0;
	let mut space_turf_len = 0;
	let mut total_moles = 0.0;
	with_adjacency_read(|graph| -> DMResult {
		while cur_queue_idx < progression_order.len() {
			let (i, m) = progression_order[cur_queue_idx];
			cur_queue_idx += 1;

			total_moles += m.total_moles();
			m.is_immutable().then(|| space_turf_len += 1);

			if cur_queue_idx > equalize_hard_turf_limit {
				continue;
			}

			for (_, _, &adj_turf) in graph.edges_directed(m.mix, petgraph::Outgoing) {
				if let Some(adj_m) = { turf_gases().get(&adj_turf) } {
					let adj_orig = info.entry(adj_turf).or_default();
					let mut adj_info = adj_orig.get();
					if !adj_m.is_immutable() && progression_order.insert((adj_turf, *adj_m)) {
						adj_info.curr_transfer_dir = Some(i);
						adj_info.curr_transfer_amount = 0.0;
						let cur_target_turf = unsafe { Value::turf_by_id_unchecked(i) }
							.get(byond_string!("pressure_specific_target"))?;
						unsafe { Value::turf_by_id_unchecked(adj_turf) }
							.set(byond_string!("pressure_specific_target"), &cur_target_turf)?;
						adj_orig.set(adj_info);
					}
				}
			}
		}
		Ok(Value::null())
	})?;

	let _average_moles = total_moles / (progression_order.len() - space_turf_len) as f32;

	let hpd = auxtools::Value::globals()
		.get(byond_string!("SSair"))?
		.get_list(byond_string!("high_pressure_delta"))
		.map_err(|_| {
			runtime!(
				"Attempt to interpret non-list value as list {} {}:{}",
				std::file!(),
				std::line!(),
				std::column!()
			)
		})?;

	//server may not have multiz, and that's fine
	let get_dir = if let Some(proc) = Proc::find(byond_string!("/proc/get_dir_multiz")) {
		proc
	} else {
		Proc::find(byond_string!("/proc/get_dir")).unwrap()
	};
	for (i, m) in progression_order.iter().rev() {
		let cur_orig = info.entry(*i).or_default();
		let mut cur_info = cur_orig.get();
		if cur_info.curr_transfer_dir.is_none() {
			continue;
		}
		let mut in_hpd = false;
		for k in 1..=hpd.len() {
			if let Ok(hpd_val) = hpd.get(k) {
				if hpd_val == unsafe { Value::turf_by_id_unchecked(*i) } {
					in_hpd = true;
					break;
				}
			}
		}
		if !in_hpd {
			hpd.append(&unsafe { Value::turf_by_id_unchecked(*i) });
		}
		let loc = cur_info.curr_transfer_dir.unwrap();
		let mut sum = 0.0_f32;

		if let Some(adj_m) = turf_gases().get(&loc) {
			sum = adj_m.total_moles();
		};

		cur_info.curr_transfer_amount += sum;
		cur_orig.set(cur_info);

		let adj_orig = info.entry(loc).or_default();
		let mut adj_info = adj_orig.get();

		adj_info.curr_transfer_amount += cur_info.curr_transfer_amount;
		adj_orig.set(adj_info);

		let byond_turf = unsafe { Value::turf_by_id_unchecked(*i) };
		let byond_turf_adj = unsafe { Value::turf_by_id_unchecked(loc) };
		byond_turf.set(
			byond_string!("pressure_difference"),
			Value::from(cur_info.curr_transfer_amount),
		)?;
		byond_turf.set(
			byond_string!("pressure_direction"),
			Value::from(get_dir.call(&[&byond_turf, &byond_turf_adj])?),
		)?;

		/*
			byond_turf_adj.set(
				byond_string!("pressure_difference"),
				Value::from(adj_info.curr_transfer_amount),
			)?;
			byond_turf_adj.set(
				byond_string!("pressure_direction"),
				Value::from(get_dir.call(&[&byond_turf_adj, &byond_turf])?),
			)?;
		*/

		#[cfg(not(feature = "katmos_slow_decompression"))]
		{
			m.clear_air();
		}
		#[cfg(feature = "katmos_slow_decompression")]
		{
			const DECOMP_REMOVE_RATIO: f32 = 4_f32;
			m.clear_vol((_average_moles / DECOMP_REMOVE_RATIO).abs());
		}

		byond_turf.call("handle_decompression_floor_rip", &[&Value::from(sum)])?;
	}
	Ok(Value::null())
	//	if (total_gases_deleted / turfs.len() as f32) > 20.0 && turfs.len() > 10 { // logging I guess
	//	}
}

// Clippy go away, this type is only used once
#[allow(clippy::type_complexity)]
fn flood_fill_equalize_turfs(
	i: TurfID,
	m: TurfMixture,
	equalize_hard_turf_limit: usize,
	found_turfs: &mut HashSet<TurfID, FxBuildHasher>,
) -> Option<(
	IndexMap<TurfID, TurfMixture, FxBuildHasher>,
	IndexMap<TurfID, TurfMixture, FxBuildHasher>,
	f64,
)> {
	let mut turfs: IndexMap<TurfID, TurfMixture, FxBuildHasher> =
		IndexMap::with_hasher(FxBuildHasher::default());
	let mut border_turfs: std::collections::VecDeque<MixWithID> = std::collections::VecDeque::new();
	let mut planet_turfs: IndexMap<TurfID, TurfMixture, FxBuildHasher> =
		IndexMap::with_hasher(FxBuildHasher::default());
	let sender = byond_callback_sender();
	let mut total_moles = 0.0_f64;
	border_turfs.push_back((i, m));
	found_turfs.insert(i);
	let mut ignore_zone = false;
	with_adjacency_read(|graph| {
		while let Some((cur_idx, cur_turf)) = border_turfs.pop_front() {
			if cur_turf.planetary_atmos.is_some() {
				planet_turfs.insert(cur_idx, cur_turf);
				continue;
			}
			total_moles += cur_turf.total_moles() as f64;

			for (_, _, &loc) in graph.edges_directed(cur_turf.mix, petgraph::Outgoing) {
				if found_turfs.insert(loc) {
					let result = turf_gases().try_get(&loc);
					if result.is_locked() {
						ignore_zone = true;
						continue;
					}
					if let Some(adj_turf) = result.try_unwrap() {
						if adj_turf.enabled() {
							border_turfs.push_back((loc, *adj_turf.value()));
						}
						if adj_turf.value().is_immutable() {
							// Uh oh! looks like someone opened an airlock to space! TIME TO SUCK ALL THE AIR OUT!!!
							// NOT ONE OF YOU IS GONNA SURVIVE THIS
							// (I just made explosions less laggy, you're welcome)
							if !ignore_zone {
								drop(sender.send(Box::new(move || {
									explosively_depressurize(i, equalize_hard_turf_limit)
								})));
							}
							ignore_zone = true;
						}
					}
				}
			}

			turfs.insert(cur_idx, cur_turf);
		}
	});
	(!ignore_zone).then(|| (turfs, planet_turfs, total_moles))
}

fn process_planet_turfs(
	planet_turfs: &IndexMap<TurfID, TurfMixture, FxBuildHasher>,
	turfs: &IndexMap<TurfID, TurfMixture, FxBuildHasher>,
	average_moles: f32,
	equalize_hard_turf_limit: usize,
	info: &DashMap<TurfID, MonstermosInfo, FxBuildHasher>,
	eq_movement_graph: &mut DiGraphMap<Option<TurfID>, f32>,
) {
	let sender = byond_callback_sender();
	let sample_turf = planet_turfs[0];
	let sample_planet_atmos = sample_turf.planetary_atmos;
	if sample_planet_atmos.is_none() {
		return;
	}
	let maybe_planet_sum = planetary_atmos()
		.try_get(&sample_planet_atmos.unwrap())
		.try_unwrap();
	if maybe_planet_sum.is_none() {
		return;
	}
	let planet_sum = maybe_planet_sum.unwrap().value().total_moles();
	let target_delta = planet_sum - average_moles;

	let mut progression_order: IndexSet<TurfID, FxBuildHasher> =
		IndexSet::with_hasher(FxBuildHasher::default());

	for (i, _) in planet_turfs.iter() {
		progression_order.insert(*i);
		let mut cur_info = info.entry(*i).or_default();
		cur_info.curr_transfer_dir = None;
	}
	// now build a map of where the path to a planet turf is for each tile.
	let mut queue_idx = 0;
	with_adjacency_read(|graph| {
		while queue_idx < progression_order.len() {
			let i = progression_order[queue_idx];
			queue_idx += 1;
			let maybe_m = turfs.get(&i);
			if maybe_m.is_none() {
				info.entry(i)
					.and_modify(|entry| *entry = MonstermosInfo::default());
				continue;
			}

			for (_, _, &adj_idx) in graph.edges_directed(maybe_m.unwrap().mix, petgraph::Outgoing) {
				if let Some(mut adj_info) = info.get_mut(&adj_idx) {
					if queue_idx < equalize_hard_turf_limit {
						drop(sender.try_send(Box::new(move || {
							let that_turf = unsafe { Value::turf_by_id_unchecked(adj_idx) };
							let this_turf = unsafe { Value::turf_by_id_unchecked(i) };
							this_turf.call("consider_firelocks", &[&that_turf])?;
							Ok(Value::null())
						})));
					}
					if let Some(adj) = turfs
						.get(&adj_idx)
						.and_then(|terf| terf.enabled().then(|| terf))
					{
						if !progression_order.insert(adj_idx) || adj.planetary_atmos.is_some() {
							continue;
						}
						adj_info.curr_transfer_dir = Some(i);
					}
				}
			}
		}
	});
	for i in progression_order.iter().rev() {
		if turfs.get(i).is_none() {
			continue;
		}
		if let Some(mut cur_info) = info.get_mut(i) {
			let airflow = cur_info.mole_delta - target_delta;
			if cur_info.curr_transfer_dir.is_none() {
				adjust_eq_movement(Some(*i), None, airflow, eq_movement_graph);
				cur_info.mole_delta = target_delta;
			} else if let Some(mut adj_info) = info.get_mut(&cur_info.curr_transfer_dir.unwrap()) {
				adjust_eq_movement(
					Some(*i),
					cur_info.curr_transfer_dir,
					airflow,
					eq_movement_graph,
				);
				adj_info.mole_delta += airflow;
				cur_info.mole_delta = target_delta;
			}
		}
	}
}

pub(crate) fn equalize(
	equalize_hard_turf_limit: usize,
	high_pressure_turfs: &Vec<TurfID>,
) -> usize {
	let turfs_processed: AtomicUsize = AtomicUsize::new(0);
	let mut found_turfs: HashSet<TurfID, FxBuildHasher> =
		HashSet::with_hasher(FxBuildHasher::default());
	let zoned_turfs = high_pressure_turfs
		.iter()
		.filter_map(|&i| {
			if found_turfs.contains(&i) {
				return None;
			};
			let m = *turf_gases().try_get(&i).try_unwrap()?;
			if with_adjacency_read(|graph| {
				!m.enabled()
					|| !graph
						.edges_directed(m.mix, petgraph::Outgoing)
						.any(|_| true) || GasArena::with_all_mixtures(|all_mixtures| {
					let our_moles = all_mixtures[m.mix].read().total_moles();
					our_moles < 10.0
						|| m.adjacent_mixes(all_mixtures, &graph).all(|lock| {
							(lock.read().total_moles() - our_moles).abs()
								< MINIMUM_MOLES_DELTA_TO_MOVE
						})
				})
			}) {
				return None;
			}
			flood_fill_equalize_turfs(i, m, equalize_hard_turf_limit, &mut found_turfs)
		})
		.collect::<Vec<_>>();

	let turfs = zoned_turfs
		.into_par_iter()
		.map(|(turfs, planet_turfs, total_moles)| {
			let info: DashMap<TurfID, MonstermosInfo, FxBuildHasher> =
				DashMap::with_hasher(FxBuildHasher::default());
			let mut graph: DiGraphMap<Option<TurfID>, f32> = Default::default();
			let average_moles = (total_moles / (turfs.len() - planet_turfs.len()) as f64) as f32;

			let (mut giver_turfs, mut taker_turfs): (Vec<_>, Vec<_>) = turfs
				.par_iter()
				.filter(|&(i, m)| {
					{
						let mut cur_info = info.entry(*i).or_default();
						cur_info.mole_delta = m.total_moles() - average_moles;
					}
					m.planetary_atmos.is_none()
				})
				.partition(|&(i, _)| info.entry(*i).or_default().mole_delta > 0.0);

			let log_n = ((turfs.len() as f32).log2().floor()) as usize;
			if giver_turfs.len() > log_n && taker_turfs.len() > log_n {
				for (&i, m) in &turfs {
					monstermos_fast_process(i, m, &turfs, &info, &mut graph);
				}
				giver_turfs.clear();
				taker_turfs.clear();

				giver_turfs.par_extend(turfs.par_iter().filter(|&(i, m)| {
					info.entry(*i).or_default().mole_delta > 0.0 && m.planetary_atmos.is_none()
				}));

				taker_turfs.par_extend(turfs.par_iter().filter(|&(i, m)| {
					info.entry(*i).or_default().mole_delta <= 0.0 && m.planetary_atmos.is_none()
				}));
			}

			// alright this is the part that can become O(n^2).
			if giver_turfs.len() < taker_turfs.len() {
				// as an optimization, we choose one of two methods based on which list is smaller.
				give_to_takers(&giver_turfs, &taker_turfs, &turfs, &info, &mut graph);
			} else {
				take_from_givers(&taker_turfs, &giver_turfs, &turfs, &info, &mut graph);
			}
			if planet_turfs.is_empty() {
				turfs_processed.fetch_add(turfs.len(), std::sync::atomic::Ordering::Relaxed);
			} else {
				turfs_processed.fetch_add(
					turfs.len() + planet_turfs.len(),
					std::sync::atomic::Ordering::Relaxed,
				);
				process_planet_turfs(
					&planet_turfs,
					&turfs,
					average_moles,
					equalize_hard_turf_limit,
					&info,
					&mut graph,
				);
			}
			(turfs, info, graph)
		})
		.collect::<Vec<_>>();

	turfs.into_par_iter().for_each(|(turf, info, mut graph)| {
		turf.iter().for_each(|(i, m)| {
			finalize_eq(*i, m, &turf, &info, &mut graph);
		});
	});
	turfs_processed.load(std::sync::atomic::Ordering::Relaxed)
}
