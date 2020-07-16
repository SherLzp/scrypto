# Credential Scheme

$Issue$：

Common inofrmation between User and Issuer:

Attributes：$k_1,...,k_n$，issuer's public key：$\sigma = (p,e,Q,A,A_0,...,A_n,Z)$

Issuer:

public $\bar{S} = \bar{K}^a,\bar{S_0} = \bar{K}^{a_0}$ where $\bar{K} \in_R G_1$

User:
$$
choose \ \alpha,\kappa' \in_R \mathbb{Z}_p^* \\set \ S = \bar{S}^{\alpha},S_0 = \bar{S_0}^{\alpha} \\PK\{(\kappa',k_0): R=S^{\kappa'} S_0^{k_0} \} \\sends \ S,S_0,R=S^{\kappa'} S_0^{k_0} \text{ to issuer}
$$
Issuer:
$$
set \ K = S^{1/a} \\verify \ S \neq \bar{S},K = S_0^{1/a_0} \\choose \ \kappa'' \in_R \mathbb{Z}_p \\set \ S_i = K^{a_i},\forall i \in[1,n] \\set \ T = (K S^{\kappa''} R \prod_{i=1}^n S_i^{k_i})^z \\sends \ \kappa'',K,S_1,...,S_n,T \text{ to user}
$$
User:
$$
set \ \kappa = \kappa' + \kappa'' \\return \ (k_0,...,k_n),(\kappa,K,S,S_0,...,S_n,T)
$$
$ShowCredential$:

Common information between User and Verifier:

Issuer's public key $\sigma = (p,e,Q,A,A_0,...,A_n,Z)$, disclosure set $\mathcal{D}$, undisclosed set $\mathcal{C} = \{1,...,n \} \setminus \mathcal{D}$, disclosed attributes: $(k_i)_{i \in D}$

User:
$$
C = K S^{\kappa} S_0^{k_0} ... S_n^{k_n} \\
knows \ K,S,S_0,...,S_n,\kappa,(k_i)_{i \in \mathcal{C}},C,T \\
choose \ \alpha,\beta \in_R \mathbb{Z}_p^* \\
set \ \bar{K} = K^{\alpha}, \bar{S} = S^{\alpha},\bar{S}_i = S_i^{\alpha} \forall i \in [0,n] \\
set \ \tilde{C} = C^{\alpha \cdot \beta}, \tilde{T} = T^{\alpha \cdot \beta} \\
set \ R = \bar{K} \prod_{i \in D} \bar{S_i}^{k_i} \\
PK\{(\beta,\kappa,k_0,(k_i)_{i \in \mathcal{C}}): \tilde{C} = R^{\beta} \bar{S}^{\kappa \cdot \beta} \bar{S_0}^{k_0 \cdot \beta} \prod_{i \in \mathcal{C}} \bar{S_i}^{k_i \cdot \beta} \} \\
sends \ \bar{K},\bar{S},(\bar{S_i})_{i=0,...,n},\tilde{C},\tilde{T} \text{ to Verifier}
$$
$Verify$:

Verifier:
$$
Verify \ ZK \ Proof \\choose \ r,r_0,...,r_n \in_R \mathbb{Z}_p^* \\
verify \ e(\tilde{C},Z) \overset{?}{=} e(\tilde{T},Q) \\
and \ e(\bar{S}^r \prod_{i=0}^n \bar{S_i}^{r_i},Q) \overset{?}{=} e(\bar{K},A^r \prod_{i=0}^n A_i^{r_i})
$$





$PK\{(\beta,\kappa,k_0,(k_i)_{i \in \mathcal{C}}): \tilde{C} = R^{\beta} \bar{S}^{\kappa \cdot \beta} \bar{S_0}^{k_0 \cdot \beta} \prod_{i \in \mathcal{C}} \bar{S_i}^{k_i \cdot \beta} \}$：

关系等式$R$：
$$
R = \bar{K} \prod_{i \in \mathcal{D}} \bar{S_i}^{k_i} \\
\tilde{C} = C^{\alpha \cdot \beta}
$$
先验证关系等式是否成立：
$$
\tilde{C} = (\bar{K} \prod_{i \in \mathcal{D}} \bar{S_i}^{k_i}) ^{\beta} \bar{S}^{\kappa \beta} \bar{S_0}^{k_0 \beta} \prod_{i \in \mathcal{C}} \bar{S_i}^{k_i \beta} \\
\tilde{C} = (K S^{\kappa} \prod_{i \in [0,n]} S_i^{k_i} )^{\alpha \beta} \\
\tilde{C} = C^{\alpha \beta}
$$
秘密：

$(\beta,\kappa \beta,(k_i \beta)_{i \in \mathcal{C}})$

已知公共参数：

$R,\bar{S},(\bar{S_i})_{i \in \mathcal{C}}$

Prover:
$$
r_i,i = [0,len(secretCount)) \in_R \mathbb{Z}_p, i \in \mathcal{C} \\
t_0 := R^{r_0},t_1 := \bar{S}^{r_1},t_i := \bar{S_i}^{r_i},i=[2,secretCount) \\
t = \prod_{i = [0,len(secretCount))} t_i \\
c = H(g \| t \| A \| H(k_i)) \\
s_0 := r_0 - c \beta\\
s_1 := r_1 - c \kappa \beta \\
s_i = r_i - c k_i \beta \\
$$
Verifier:
$$
t = R^{s_0} \cdot \bar{S}^{s_1} \cdot \bar{S_i}^{s_i} \cdot \tilde{C}^{c} \\
t = R^{s_0} \cdot \bar{S}^{s_1} \cdot \bar{S_i}^{s_i} \cdot (\bar{C}^{\beta})^{c} \\
t = (R)^{r_0 - c\beta} \cdot \bar{S}^{r_1 - c \kappa \beta} \cdot (\prod_{i \in \mathcal{C}} \bar{S_i}^{r_i - c k_i \beta}) \cdot (R \cdot \bar{S} \cdot \prod_{i \in \mathcal{C}}\bar{S_i}^{k_i})^{c \beta} \\
t = R^{r_0} \cdot \bar{S}^{r_1} \cdot \prod_{i \in \mathcal{C}}\bar{S_i}^{k_i} \\
t = \prod_{i = [0,n]} t_i
$$

# References

Ringers S, Verheul E, Hoepman J H. An efficient self-blindable attribute-based credential scheme[C]//International Conference on Financial Cryptography and Data Security. Springer, Cham, 2017: 3-20.