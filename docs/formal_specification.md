# Aletheia Formal Cryptographic Specification

> **Version**: 1.0.0  
> **Standards**: RFC 6962 (Certificate Transparency Merkle Trees) | RFC 8785 (JSON Canonicalization Scheme) | FRE 902(14) | ISO/IEC 27037

---

## 1. Mathematical Definitions & Primitives

Let $\Sigma$ denote the alphabet of octets (bytes), and $\Sigma^*$ the set of finite byte strings.  
Let $\mathcal{H}: \Sigma^* \to \{0, 1\}^{256}$ denote the cryptographic hash function **SHA-256** (FIPS 180-4).  
Let $\mathcal{C}: \mathcal{O} \to \Sigma^*$ denote the **RFC 8785 JSON Canonicalization Scheme (JCS)** mapping arbitrary JSON objects to a canonical byte representation.

### 1.1 RFC 6962 Domain Separation Invariant

To prevent second-preimage attacks between leaf nodes and internal tree nodes, domain prefixes are prepended prior to hashing:

$$\text{PREFIX}_{\text{LEAF}} = 0\text{x}00 \in \Sigma^1$$
$$\text{PREFIX}_{\text{NODE}} = 0\text{x}01 \in \Sigma^1$$

For any leaf event $e_i \in \mathcal{E}$, the leaf hash $h_i^{(0)}$ is defined as:

$$h_i^{(0)} = \mathcal{H}\left(\text{PREFIX}_{\text{LEAF}} \,\|\, \mathcal{C}(e_i)\right)$$

For any two adjacent nodes $L, R \in \{0, 1\}^{256}$ at level $k$, the parent internal node $P$ is computed as:

$$P = \mathcal{H}\left(\text{PREFIX}_{\text{NODE}} \,\|\, L \,\|\, R\right)$$

**Theorem 1 (Collision Resistance Between Tiers)**:  
Given the collision resistance of $\mathcal{H}$, for any leaf input $x$ and any internal pair $(L, R)$, $\text{PREFIX}_{\text{LEAF}} \,\|\, x \neq \text{PREFIX}_{\text{NODE}} \,\|\, L \,\|\, R$ unconditionally because their first bytes differ ($0\text{x}00 \neq 0\text{x}01$). Thus:

$$\mathcal{H}(\text{PREFIX}_{\text{LEAF}} \,\|\, x) \neq \mathcal{H}(\text{PREFIX}_{\text{NODE}} \,\|\, L \,\|\, R)$$

No leaf node can masquerade as an interior tree branch.

---

## 2. Ingestion & Merkle Tree Construction

Let an acquired evidence case contain a set of $n$ discrete forensic events:

$$\mathcal{E} = \{e_1, e_2, \dots, e_n\}$$

### 2.1 Canonical Ordering
To guarantee deterministic execution independent of operating system file enumeration order:
1. Every event $e_i$ is mapped to its SHA-256 digest $k_i = \mathcal{H}(\mathcal{C}(e_i))$.
2. The leaf set is sorted in ascending lexicographical order:

$$k_{(1)} \le k_{(2)} \le \dots \le k_{(n)}$$

### 2.2 Odd-Leaf Promotion Rule
If the cardinality of nodes at level $k$ is odd ($|L_k| = 2m + 1$), the trailing node $L_k[2m]$ is paired with itself under the internal prefix:

$$P_{\text{odd}} = \mathcal{H}\left(\text{PREFIX}_{\text{NODE}} \,\|\, L_k[2m] \,\|\, L_k[2m]\right)$$

The tree collapses iteratively until $|L_{\text{root}}| = 1$, yielding the root digest:

$$\mathcal{R} = \text{MerkleTree}(\mathcal{E}) \in \{0, 1\}^{256}$$

For an empty set $\mathcal{E} = \emptyset$:
$$\text{MerkleTree}(\emptyset) = 0^{64} \in \Sigma^{32}$$

---

## 3. Blockchain State Transition Rules

The on-chain smart contract $\mathcal{S}$ (`AletheiaRegistry.sol`) maintains state $\sigma = (\mathcal{K}, \mathcal{C}, \mathcal{L}, \mathcal{A})$ where:
- $\mathcal{K}: \text{Address} \to \text{Bool}$ (Revoked investigator set).
- $\mathcal{C}: \text{Bytes32} \to \text{CaseEvidence}$ (Case registry records).
- $\mathcal{L}: \text{Bytes32} \to \text{Bytes32}$ (Ingestion manifest commitments).
- $\mathcal{A}: \text{Bytes32} \to \text{Address}$ (Co-signer peer attestations).

### Transition 1: Ingestion Commitment
$$\text{anchorIngestionCommitment}(c, m) \implies \mathcal{L}[c] \gets m$$
*Preconditions*: $c \neq 0$, $m \neq 0$, $\mathcal{K}[\text{msg.sender}] = \text{False}$.

### Transition 2: Case Registration
$$\text{registerCase}(c, \mathcal{R}, s_{\text{raw}}, \text{cid}, n) \implies \mathcal{C}[c] \gets (c, \mathcal{R}, s_{\text{raw}}, \text{cid}, \text{msg.sender}, \tau, n, \text{true})$$
*Preconditions*: $\mathcal{C}[c].\text{registeredAt} = 0$ (Immutability guarantee).

### Transition 3: Mandatory Peer Co-Signing
$$\text{coSignCase}(c) \implies \mathcal{A}[c] \gets \text{msg.sender}$$
*Preconditions*: $\mathcal{C}[c].\text{registeredAt} \neq 0$, $\text{msg.sender} \neq \mathcal{C}[c].\text{leadInvestigator}$, $\mathcal{K}[\text{msg.sender}] = \text{False}$.

---

## 4. Verification Predicate

Given local evidence $\mathcal{E}'$ and an on-chain case identifier $c$, the verification predicate $\mathcal{V}(\mathcal{E}', c)$ evaluates to $\text{TRUE}$ if and only if:

$$\mathcal{V}(\mathcal{E}', c) \iff \left(\text{MerkleTree}(\mathcal{E}') = \mathcal{C}[c].\mathcal{R}\right) \land \left(\mathcal{H}(\text{raw\_manifest}) = \mathcal{L}[c]\right) \land \left(\mathcal{A}[c] \neq 0\right)$$

Any mutation $\Delta \in \Sigma^*$ introduced into any event $e_i \in \mathcal{E}'$ alters $h_i^{(0)}$ with probability $1 - 2^{-256}$, causing $\text{MerkleTree}(\mathcal{E}') \neq \mathcal{C}[c].\mathcal{R}$ and failing the verification predicate.
