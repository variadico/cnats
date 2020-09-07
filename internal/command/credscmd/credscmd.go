package credscmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/bcrypt"
)

type keyer interface {
	PublicKey() (string, error)
	PrivateKey() ([]byte, error)
	Seed() ([]byte, error)
}

type options struct {
	credsFile     string
	operatorName  string
	accountName   string
	userName      string
	issuerKeys    nkeys.KeyPair
	outputFields  []string
	showAll       bool
	bcrypt        bool
	natsClaims    []byte
	setNATSClaims bool
}

func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "creds",
		Short:         "Manage authentication and authorization",
		RunE:          runE,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.Flags().String("new-operator", "", "create operator with name")
	cmd.Flags().String("new-account", "", "create new account with name")
	cmd.Flags().String("new-user", "", "create new user with name")
	cmd.Flags().String("set-nats-claims", "", "set entity nats claims")
	cmd.Flags().StringP("issuer", "i", "", "issuer credentials")
	cmd.Flags().BoolP("all", "A", false, "show all credential data")
	cmd.Flags().BoolP("bcrypt", "b", false, "hash stdin with bcrypt")
	cmd.Flags().StringP("output-fields", "f", "", "comma separated list of fields to include in output")

	return cmd
}

func runE(cmd *cobra.Command, args []string) error {
	opt, err := getOptions(cmd.Flags(), args)
	if err != nil {
		return fmt.Errorf("failed to get options: %w", err)
	}

	switch {
	case opt.operatorName != "":
		credsFile, err := newOperator(opt)
		if err != nil {
			return err
		}

		fmt.Print(credsFile)
	case opt.accountName != "":
		credsFile, err := newAccount(opt)
		if err != nil {
			return err
		}

		fmt.Print(credsFile)
	case opt.userName != "":
		credsFile, err := newUser(opt)
		if err != nil {
			return err
		}

		fmt.Print(credsFile)
	case opt.bcrypt:
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		s, err := bcryptData(data)
		if err != nil {
			return err
		}

		fmt.Println(s)
	case opt.setNATSClaims:
		credsFile, err := updateNATSClaims(opt)
		if err != nil {
			return err
		}

		fmt.Print(credsFile)
	default:
		credsOutput, err := readCreds(opt)
		if err != nil {
			return err
		}
		fmt.Println(credsOutput)
	}

	return nil
}

func getOptions(flags *pflag.FlagSet, args []string) (options, error) {
	var opt options
	var err error

	opt.operatorName, err = flags.GetString("new-operator")
	if err != nil {
		return options{}, err
	}
	if flags.Changed("new-operator") && opt.operatorName == "" {
		return options{}, fmt.Errorf("operator name cannot be empty")
	}

	opt.accountName, err = flags.GetString("new-account")
	if err != nil {
		return options{}, err
	}
	if flags.Changed("new-account") && opt.accountName == "" {
		return options{}, fmt.Errorf("account name cannot be empty")
	}

	opt.userName, err = flags.GetString("new-user")
	if err != nil {
		return options{}, err
	}
	if flags.Changed("new-user") && opt.userName == "" {
		return options{}, fmt.Errorf("user name cannot be empty")
	}

	needIssuer := flags.Changed("new-account") || flags.Changed("new-user")

	issuerCredsFile, err := flags.GetString("issuer")
	if err != nil {
		return options{}, err
	}
	if needIssuer && issuerCredsFile == "" {
		return options{}, fmt.Errorf("issuer cannot be empty")
	} else if needIssuer && issuerCredsFile != "" {
		data, err := ioutil.ReadFile(issuerCredsFile)
		if err != nil {
			return options{}, err
		}
		opt.issuerKeys, err = jwt.ParseDecoratedNKey(data)
		if err != nil {
			return options{}, err
		}
	}

	if flags.Changed("set-nats-claims") && flags.Changed("issuer") {
		data, err := ioutil.ReadFile(issuerCredsFile)
		if err != nil {
			return options{}, err
		}
		opt.issuerKeys, err = jwt.ParseDecoratedNKey(data)
		if err != nil {
			return options{}, err
		}
	}

	opt.showAll, err = flags.GetBool("all")
	if err != nil {
		return options{}, err
	}

	opt.bcrypt, err = flags.GetBool("bcrypt")
	if err != nil {
		return options{}, err
	}

	noCredsFlag := flags.Changed("new-operator") ||
		flags.Changed("new-account") || flags.Changed("new-user") || flags.Changed("bcrypt")
	if !noCredsFlag && len(args) == 0 {
		return options{}, fmt.Errorf("missing credentials file")
	} else if len(args) > 0 {
		opt.credsFile = args[0]
	}

	outputFields, err := flags.GetString("output-fields")
	if err != nil {
		return options{}, err
	}
	if outputFields != "" {
		for _, s := range strings.Split(outputFields, ",") {
			opt.outputFields = append(opt.outputFields, strings.TrimSpace(s))
		}
	}

	natsClaims, err := flags.GetString("set-nats-claims")
	if err != nil {
		return options{}, err
	}
	opt.natsClaims = []byte(natsClaims)
	opt.setNATSClaims = flags.Changed("set-nats-claims")

	return opt, nil
}

func newOperator(opt options) (string, error) {
	keyPair, err := nkeys.CreateOperator()
	if err != nil {
		return "", err
	}

	publicKey, err := keyPair.PublicKey()
	if err != nil {
		return "", err
	}

	claims := jwt.NewOperatorClaims(publicKey)
	claims.Name = opt.operatorName

	if opt.setNATSClaims {
		r := bytes.NewReader(opt.natsClaims)
		dec := json.NewDecoder(r)
		dec.DisallowUnknownFields()

		var natsClaims jwt.Operator
		if err := dec.Decode(&natsClaims); err != nil {
			return "", err
		}
		claims.Operator = natsClaims
	}

	ct, err := claims.Encode(keyPair)
	if err != nil {
		return "", err
	}

	seed, err := keyPair.Seed()
	if err != nil {
		return "", err
	}

	return formatCredsFile(ct, seed)
}

func newAccount(opt options) (string, error) {
	keyPair, err := nkeys.CreateAccount()
	if err != nil {
		return "", err
	}

	publicKey, err := keyPair.PublicKey()
	if err != nil {
		return "", err
	}

	claims := jwt.NewAccountClaims(publicKey)
	claims.Name = opt.accountName
	// Set other claims, claims.nats or something

	ct, err := claims.Encode(opt.issuerKeys)
	if err != nil {
		return "", err
	}

	seed, err := keyPair.Seed()
	if err != nil {
		return "", err
	}

	return formatCredsFile(ct, seed)
}

func newUser(opt options) (string, error) {
	keyPair, err := nkeys.CreateUser()
	if err != nil {
		return "", err
	}

	publicKey, err := keyPair.PublicKey()
	if err != nil {
		return "", err
	}

	claims := jwt.NewUserClaims(publicKey)
	claims.Name = opt.userName
	// Set other claims, claims.nats or something

	ct, err := claims.Encode(opt.issuerKeys)
	if err != nil {
		return "", err
	}

	seed, err := keyPair.Seed()
	if err != nil {
		return "", err
	}

	return formatCredsFile(ct, seed)
}

func formatCredsFile(configToken string, seed []byte) (string, error) {
	decToken, err := jwt.DecorateJWT(configToken)
	if err != nil {
		return "", err
	}

	decSeed, err := jwt.DecorateSeed(seed)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s%s", decToken, decSeed), nil
}

type naKeyPair struct{}

func (kp naKeyPair) PublicKey() (string, error) {
	return "N/A", nil
}
func (kp naKeyPair) PrivateKey() ([]byte, error) {
	return []byte("N/A"), nil
}
func (kp naKeyPair) Seed() ([]byte, error) {
	return []byte("N/A"), nil
}

func readCreds(opt options) (s string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to read ncreds: %w", err)
		}
	}()

	creds, err := ioutil.ReadFile(opt.credsFile)
	if err != nil {
		return "", err
	}

	configToken, err := jwt.ParseDecoratedJWT(creds)
	if err != nil {
		return "", fmt.Errorf("failed to read config token: %w", err)
	}

	claims, err := jwt.DecodeGeneric(configToken)
	if err != nil {
		return "", fmt.Errorf("failed to read claims: %w", err)
	}

	var keys keyer
	keys, err = jwt.ParseDecoratedNKey(creds)
	if err != nil {
		if !strings.Contains(err.Error(), "no nkey seed found") {
			return "", err
		}
		keys = naKeyPair{}
	}

	return formatCredsOutput(claims, configToken, keys, opt)
}

func formatCredsOutput(gc *jwt.GenericClaims, token string, kp keyer, opt options) (string, error) {
	claims, err := json.Marshal(gc)
	if err != nil {
		return "", err
	}

	if !opt.showAll && len(opt.outputFields) == 0 {
		return string(claims), nil
	}

	publicKey, err := kp.PublicKey()
	if err != nil {
		return "", err
	}
	privateKey, err := kp.PrivateKey()
	if err != nil {
		return "", err
	}
	seed, err := kp.Seed()
	if err != nil {
		return "", err
	}

	m := map[string]string{
		"claims":        string(claims),
		"claimsencoded": string(token),
		"publickey":     string(publicKey),
		"privatekey":    string(privateKey),
		"seed":          string(seed),
	}

	if opt.showAll && len(opt.outputFields) == 0 {
		opt.outputFields = append(opt.outputFields, "claims", "claimsencoded", "publickey",
			"privatekey", "seed")
	}

	var chunks []string
	for _, f := range opt.outputFields {
		f = strings.ToLower(f)
		if v, ok := m[f]; ok {
			chunks = append(chunks, v)
		}
	}

	return strings.Join(chunks, "\t"), nil
}

func bcryptData(bs []byte) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(bs, 11)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func updateNATSClaims(opt options) (s string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to set nats claims: %w", err)
		}
	}()

	creds, err := ioutil.ReadFile(opt.credsFile)
	if err != nil {
		return "", fmt.Errorf("failed to read ncreds file: %w", err)
	}

	configToken, err := jwt.ParseDecoratedJWT(creds)
	if err != nil {
		return "", fmt.Errorf("failed to read config token: %w", err)
	}

	keys, err := jwt.ParseDecoratedNKey(creds)
	if err != nil {
		return "", fmt.Errorf("failed to read nkeys: %w", err)
	}

	r := bytes.NewReader(opt.natsClaims)
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	entity, err := tokenEntity(configToken)
	if err != nil {
		return "", fmt.Errorf("failed to find config token type: %w", err)
	}

	var credsFile string
	switch entity {
	case "operator":
		credsFile, err = updateNATSClaimsOperator(configToken, keys, dec)
	case "account":
		credsFile, err = updateNATSClaimsAccount(configToken, keys, opt.issuerKeys, dec)
	case "user":
		credsFile, err = updateNATSClaimsUser(configToken, keys, opt.issuerKeys, dec)
	default:
		err = fmt.Errorf("unable to determine config token type")
	}
	if err != nil {
		return "", err
	}

	return credsFile, nil
}

func updateNATSClaimsOperator(configToken string, oprKeys nkeys.KeyPair, d *json.Decoder) (string, error) {
	claims, err := jwt.DecodeOperatorClaims(configToken)
	if err != nil {
		return "", err
	}

	var natsClaims jwt.Operator
	if err := d.Decode(&natsClaims); err != nil {
		return "", err
	}
	claims.Operator = natsClaims

	ct, err := claims.Encode(oprKeys)
	if err != nil {
		return "", err
	}

	seed, err := oprKeys.Seed()
	if err != nil {
		return "", err
	}

	return formatCredsFile(ct, seed)
}

func updateNATSClaimsAccount(configToken string, accKeys, oprKeys nkeys.KeyPair, d *json.Decoder) (string, error) {
	if oprKeys == nil {
		return "", fmt.Errorf("missing operator issuer ncreds")
	}

	claims, err := jwt.DecodeAccountClaims(configToken)
	if err != nil {
		return "", err
	}

	var natsClaims jwt.Account
	if err := d.Decode(&natsClaims); err != nil {
		return "", err
	}
	claims.Account = natsClaims

	ct, err := claims.Encode(oprKeys)
	if err != nil {
		return "", err
	}

	seed, err := accKeys.Seed()
	if err != nil {
		return "", err
	}

	return formatCredsFile(ct, seed)
}

func updateNATSClaimsUser(configToken string, usrKeys, accKeys nkeys.KeyPair, d *json.Decoder) (string, error) {
	if accKeys == nil {
		return "", fmt.Errorf("missing account issuer ncreds")
	}

	claims, err := jwt.DecodeUserClaims(configToken)
	if err != nil {
		return "", err
	}

	var natsClaims jwt.User
	if err := d.Decode(&natsClaims); err != nil {
		return "", err
	}
	claims.User = natsClaims

	ct, err := claims.Encode(accKeys)
	if err != nil {
		return "", err
	}

	seed, err := usrKeys.Seed()
	if err != nil {
		return "", err
	}

	return formatCredsFile(ct, seed)
}

func tokenEntity(configToken string) (string, error) {
	sps := strings.Split(configToken, ".")
	if len(sps) < 2 {
		fmt.Fprintln(os.Stderr, sps)
		return "", fmt.Errorf("unexpected number of token splits: %d", len(sps))
	}


	data, err := base64.RawStdEncoding.DecodeString(sps[1])
	if err != nil {
		return "", err
	}

	data = bytes.ReplaceAll(data, []byte(" "), []byte(""))

	switch {
	case bytes.Contains(data, []byte(`"type":"operator"`)):
		return "operator", nil
	case bytes.Contains(data, []byte(`"type":"account"`)):
		return "account", nil
	case bytes.Contains(data, []byte(`"type":"user"`)):
		return "user", nil
	}

	return "", nil
}
