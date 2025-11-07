#ifndef __MAPS_BPF_H
#define __MAPS_BPF_H

#include <bpf/bpf_helpers.h>

// Helper function to increment map value
static __always_inline int increment_map(void *map, void *key, u64 increment)
{
    u64 *value, new_value = increment;

    value = bpf_map_lookup_elem(map, key);
    if (value) {
        new_value = *value + increment;
    }

    bpf_map_update_elem(map, key, &new_value, BPF_ANY);

    return 0;
}

#endif /* __MAPS_BPF_H */
