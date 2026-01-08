from typing import NewType, NamedTuple, Set
from musig import *
import secrets
import itertools

def eval_lagrange(indices: Set[int], excluding: int, eval_at: int, modulus: int = n) -> int:
    if excluding in indices:
        indices.remove(excluding)

    numerator = 1
    denominator = 1
    for index in indices:
        numerator = (numerator * (index - eval_at)) % modulus
        denominator = (denominator * (index - excluding)) % modulus

    return (numerator * pow(denominator, -1, modulus)) % modulus

def all_lagrange_coefficients(indices: Set[int], modulus: int = n) -> dict[int, List[int]]:
    from numpy import poly1d, polyval
    X = poly1d([1, 0])

    L = poly1d([1])
    for index in indices:
        L = L * (X - index)

    result = {}
    for j in indices:
        L_j = (L / (X - j))[0]
        denominator_inv = pow(int(polyval(L_j, j)), -1, modulus)
        coefficients = [(int(c) * denominator_inv) % modulus for c in L_j.coeffs]
        coefficients.reverse()
        result[j] = coefficients

    return result

def lagrange_coefficients(indices: Set[int], excluding: int, modulus: int = n) -> List[int]:
    from numpy import poly1d
    X = poly1d([1, 0])

    if excluding in indices:
        indices.remove(excluding)

    numerator = poly1d([1])
    denominator = 1
    for index in indices:
        numerator = numerator * (index - X)
        numerator = poly1d(numerator.coeffs.astype(object) % modulus)
        denominator = (denominator * (index - excluding)) % modulus

    denominator_inv = pow(denominator, -1, modulus)
    coefficients = [(int(c) * denominator_inv) % modulus for c in numerator.coefficients]
    coefficients.reverse()
    return coefficients

def lagrange_coefficient(indices: Set[int], excluding: int, power: int = 0, modulus: int = n) -> int:
    if power == 0: # Computing the constant term is the same as evaluating X = 0
        return eval_lagrange(indices, excluding, 0, modulus)
    else:
        return lagrange_coefficients(indices, excluding, modulus)[power]

RSSSummand = NamedTuple('RSSSubShare', [('value', bytes), ('excluded_indices', Set)])
RSSShare = NewType('RSSShare', List[RSSSummand])
VPSSGenShare = NamedTuple('VPSSGenShare', [('index', int), ('value', bytes)])
VPSSCommitment = NamedTuple('VPSSCommitment', [('index', int), ('value', bytes)])

def prf(key: bytes, msg: bytes) -> int:
    return int_from_bytes(tagged_hash('VPSS/prf', key + msg))

def key_gen(n: int, t: int, mu: int) -> List[RSSShare]:
    assert mu >= 2*t - 1
    unqualified_sets = [set(comb) for comb in itertools.combinations(range(1, n+1), t-1)]

    sks = [RSSShare([]) for _ in range(n)]
    for comb in unqualified_sets:
        phi_i = secrets.token_bytes(32)
        summand_i = RSSSummand(phi_i, comb)
        for j in range(n):
            if j+1 not in comb:
                sks[j].append(summand_i)

    return sks

def gen(k: int, sk_k: RSSShare, w: bytes) -> Tuple[VPSSGenShare, VPSSCommitment]:
    d_k = 0
    for (phi_i, a_i) in sk_k:
        d_k = (d_k + prf(phi_i, w) * eval_lagrange(a_i, 0, k)) % n
    D_k = point_mul(G, d_k)
    return VPSSGenShare(k, bytes_from_int(d_k)), VPSSCommitment(k, cbytes_ext(D_k))

def verify(t: int, mu: int, commitments: List[VPSSCommitment]) -> bool:
    if len(commitments) < mu:
        return False

    coefficients = all_lagrange_coefficients(set([j for j, _ in commitments]))
    for i in range(t, len(commitments)):
        B_i = infinity
        for j, D_j in commitments:
            coefficient_i = coefficients[j][i] if len(coefficients[j]) > i else 0
            B_i = point_add(B_i, point_mul(cpoint_ext(D_j), coefficient_i))

        if B_i != infinity:
            return False

    return True

def agg(commitments: List[VPSSCommitment]) -> bytes:
    result = infinity
    for j, D_j in commitments:
        indices = set([i for i, _ in commitments])
        result = point_add(result, point_mul(cpoint_ext(D_j), eval_lagrange(indices, j, 0)))

    return cbytes_ext(result)

def recover(mu, shares: List[VPSSGenShare]) -> Tuple[bytes, bytes]:
    assert len(shares) >= mu
    Ds = {}
    for j, d_j in shares:
        assert 1 <= j <= n
        Ds[j] = point_mul(G, int_from_bytes(d_j))
    # assert verify(t, mu, VPSSContext([VPSSCommitment(j, Ds[j]) for j, _ in shares]))

    d = 0
    for j, d_j in shares:
        indices = set([i for i, _ in shares])
        d = (d + int_from_bytes(d_j) * eval_lagrange(indices, j, 0)) % n
    D = point_mul(G, d)

    return bytes_from_int(d), cbytes_ext(D)

def test_random(n: int, t: int, mu: int):
    secret_shares = key_gen(n, t, mu)
    merged_summands = set()
    for share in secret_shares:
        merged_summands = merged_summands.union(set([phi for phi, _ in share]))

    msg = bytes_from_int(42)
    agg_secret = 0
    for k in merged_summands:
        import musig
        agg_secret = (agg_secret + prf(k, msg)) % musig.n
    agg_secret_commitment = cbytes_ext(point_mul(G, agg_secret))

    ds = {}
    Ds = {}
    for k, sk_k in enumerate(secret_shares, start=1):
        ds[k], Ds[k] = gen(k, sk_k, msg)
        assert (ds[k][0] == Ds[k][0] == k)
        assert cbytes_ext(point_mul(G, int_from_bytes(ds[k][1]))) == Ds[k][1]

    for sub_ds in itertools.combinations(list(ds.values()), mu):
        sub_Ds = [VPSSCommitment(k, cbytes_ext(point_mul(G, int_from_bytes(d_k)))) for k, d_k in sub_ds]
        assert verify(t, mu, sub_Ds)
        assert int_from_bytes(recover(mu, list(sub_ds))[0]) == agg_secret
        assert recover(mu, list(sub_ds))[1] == agg_secret_commitment
        assert agg(list(sub_Ds)) == agg_secret_commitment

    print('Success!')