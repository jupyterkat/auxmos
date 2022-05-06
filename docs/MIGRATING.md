# 0.2 to 0.3

If you're using generic fires, `fire_enthalpy_released` was replaced with a more general `enthalpy`. If you're not, you don't need to do anything in auxgm.

# 0.3 to 1.0

New functions were added:

1. `/datum/gas_mixture/proc/adjust_moles_temp(gas_type, amt, temperature)`
2. `/datum/gas_mixture/proc/adjust_multi()` (it's variadic, of the form `gas1, amt1, gas2, amt2, ...`)
3. `/datum/gas_mixture/proc/add(amt)`
4. `/datum/gas_mixture/proc/subtract(amt)`
5. `/datum/gas_mixture/proc/multiply(factor)`
6. `/datum/gas_mixture/proc/divide(factor)`
7. `/datum/gas_mixture/proc/__remove_by_flag(taker, flag, amount)` should be paired with a proper remove_by_flag, like remove and remove_ratio
8. `/datum/gas_mixture/proc/get_by_flag(flag)`

There's also new feature flags:

1. `turf_processing`: on by default. Enables the hooks for turf processing, heat processing etc. Required for katmos, of course.
2. `zas_hooks`: Adds a `/datum/gas_mixture/proc/share_ratio(sharer, ratio, share_size, one_way = FALSE)` hook.

Monstermos is now deprecated. Use katmos instead. It inherently has explosive decompression, sorry.

`fire_products = "plasma_fire"` should be replaced with `fire_products = 0` or, preferably, `fire_products = FIRE_PRODUCT_PLASMA` or similar, with `FIRE_PRODUCT_PLASMA` being `#define FIRE_PRODUCT_PLASMA 0`. String conversion like this is why fires weren't working on linux before; this breaking change is required for it not to be a total hack.

