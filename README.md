# Microcoins

**The author is NOT a cryptographer and has not tested the libraries used or the code nor has anyone reviewed the work. This means it's very likely the implementation contains bugs and even fatal flaws. This is only meant as an educational content and is not production ready. It may also not be exactly the way it was envisioned in the paper so mistakes come from the author of this repository and not the paper itself.**

Minimal implementation of ecash which is mostly based on Micali and Rivest's work [1] [2]. The implementation mostly follow the variant named MR-01, but has some modifications. The scheme requires deterministic signatures to prevent the merchant from manipulating the payability of the check. We use implementation of VRF from Algorand repository [3] to achieve that. Note that the repository claims **the code wasn't audited** yet. This implementation is very slow due to the slow implementation of ECC operations.

_NOTE: A serious implementation would use better data structures and have all kinds of security measures that this one lacks including code audit, locking for atomic updates, patching resource attack vectors etc._


### References:

[1] - https://people.csail.mit.edu/rivest/pubs/MR02a.prepub.pdf

[2] - https://www.youtube.com/watch?v=xgA6TO7drok

[3] - https://github.com/algorand/vrf/