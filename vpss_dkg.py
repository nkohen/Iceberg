from vpss import *
from musig import *
import math

# Returns the lexicographical index of exclusion_set
# E.g., if n=4 and t=3, then {1,2} has index 0, {1,4} has index 1, and {3,4} has index 5.
def index_from_set(n: int, t: int, exclusion_set: Set[int]) -> int:
    assert len(exclusion_set) == t - 1
    index = 0
    remaining_elements = t-1
    for j in range(1, n):
        if remaining_elements == 0:
            break
        if j in exclusion_set:
            remaining_elements -= 1
        else:
            index += math.comb(n-j, remaining_elements-1)
    return index

# Returns the set of t-1 elements of {1, ..., n} with the given lexicographical index.
# E.g., if n=4 and t=3, then {1,2} has index 0, {1,4} has index 1, and {3,4} has index 5.
def set_from_index(n: int, t: int, index: int) -> Set[int]:
    if index == 0:
        return set(range(1, t))
    no_one_index = math.comb(n-1, t-2)
    if index < no_one_index:
        result = {i+1 for i in set_from_index(n-1, t-1, index)}
        result.add(1)
        return result
    else:
        return {i+1 for i in set_from_index(n-1, t, index - no_one_index)}

def serialize_summand(n: int, t: int, summand: RSSSummand) -> bytes:
    index = index_from_set(n, t, summand.excluded_indices)
    return bytes_from_int(index) + summand.value

def deserialize_summand(n: int, t: int, summand: bytes) -> RSSSummand:
    index = int_from_bytes(summand[0:32])
    excluded_indices = set_from_index(n, t, index)
    return RSSSummand(summand[32:64], excluded_indices)

# RSS DKG where the lowest index party in the complement of each maximal unqualified set is responsible
# for generating and sharing the corresponding secret. During the second round each party signs the hashes
# of all of their secrets and verifies everyone else's signatures to ensure everyone has the same state.
def dkg_round_1(k: int, n: int, t: int, mu: int) -> List[RSSSummand]:
    assert n >= mu
    assert mu >= 2*t - 1

    if k > t:
        return []

    prefix = range(1, k)
    result = []
    for comb in itertools.combinations(range(k+1, n+1), t-(k-1)):
        exclusion_set = set(comb).union(prefix)
        phi = secrets.token_bytes(32) # Should actually be encrypted to each recipient
        result.append(RSSSummand(phi, exclusion_set))

    return result

def dkg_round_2(sk_k: RSSShare) -> List[bytes]:
    # Return signatures of hash for each decrypted summand value in sk_k
    return []

def dkg_verify(hashes: List[bytes], sigs: List[bytes]) -> bool:
    # Verify each signature and verify all required keys were used
    return True