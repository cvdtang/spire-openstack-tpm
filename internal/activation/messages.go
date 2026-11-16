package activation

// AttestVersion is the version of the messages between the agent and server plugins.
const AttestVersion = 1

// AttestPayload is the agent's first message.
type AttestPayload struct {
	Version  int    `json:"version"`
	Cert     []byte `json:"cert"`      // DER, the instance's certificate from NV
	AKPublic []byte `json:"ak_public"` // marshaled TPMT_PUBLIC of the AK
}

// Challenge is TPM2_MakeCredential's output for the certified key and the AK's name.
type Challenge struct {
	IDObject  []byte `json:"id_object"`
	EncSecret []byte `json:"enc_secret"`
}

// ChallengeResponse is the activated secret.
type ChallengeResponse struct {
	Secret []byte `json:"secret"`
}
