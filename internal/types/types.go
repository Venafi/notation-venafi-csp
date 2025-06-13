package types

type SigningMethod struct {
	Mechanism int
	KeySize   int
	Hash      string
}
