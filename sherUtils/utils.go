package sherUtils

func ContactBytes(a, b []byte, in ...[]byte) (res []byte) {
	contact := func(_a, _b []byte) (_res []byte) {
		_res = append(_a, _b...)
		return _res
	}
	res = append(a, b...)
	for i := 0; i < len(in); i++ {
		res = contact(res, in[i])
	}
	return res
}
