#include "oram_utils.hpp"

void oarraySearch(uint32_t *array, uint32_t loc, uint32_t *leaf, uint32_t new_label, uint32_t N_level) {
    for(uint32_t i = 0; i < N_level; i++) {
        omove(i, &(array[i]), loc, leaf, new_label);
    }
    return;
}