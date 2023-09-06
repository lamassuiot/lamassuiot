package api

type CaCertsLogSerialized struct {
	TotalCas int `json:"total_cas"`
}

func (s *GetCasOutput) ToSerializedLog() CaCertsLogSerialized {
	return CaCertsLogSerialized{
		TotalCas: len(s.Certs),
	}
}

type EnrollLogSerialized struct {
	CommonName string `json:"common_name"`
	IssuerName string `json:"issuer_name"`
}

func (s *EnrollOutput) ToSerializedLog() EnrollLogSerialized {
	return EnrollLogSerialized{
		CommonName: s.Cert.Subject.CommonName,
		IssuerName: s.Cert.Issuer.CommonName,
	}
}

type ReenrollLogSerialized struct {
	CommonName string `json:"common_name"`
	IssuerName string `json:"issuer_name"`
}

func (s *ReenrollOutput) ToSerializedLog() ReenrollLogSerialized {
	return ReenrollLogSerialized{
		CommonName: s.Cert.Subject.CommonName,
		IssuerName: s.Cert.Issuer.CommonName,
	}
}

type ServerKeyGenLogSerialized struct {
	CommonName string `json:"common_name"`
	IssuerName string `json:"issuer_name"`
}

func (s *ServerKeyGenOutput) ToSerializedLog() ServerKeyGenLogSerialized {
	return ServerKeyGenLogSerialized{
		CommonName: s.Cert.Subject.CommonName,
		IssuerName: s.Cert.Issuer.CommonName,
	}
}
