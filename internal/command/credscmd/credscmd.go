package credscmd

import (
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
	issuerKeyPair nkeys.KeyPair
	outputFields  []string
	showAll       bool
	bcrypt        bool
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
	default:
		creds, err := ioutil.ReadFile(opt.credsFile)
		if err != nil {
			return err
		}

		credsOutput, err := readCreds(creds, opt)
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
		opt.issuerKeyPair, err = jwt.ParseDecoratedNKey(data)
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
	// Set claims.operator_service_urls

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

	ct, err := claims.Encode(opt.issuerKeyPair)
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

	ct, err := claims.Encode(opt.issuerKeyPair)
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

func readCreds(creds []byte, opt options) (string, error) {
	configToken, err := jwt.ParseDecoratedJWT(creds)
	if err != nil {
		return "", err
	}

	claims, err := jwt.DecodeGeneric(configToken)
	if err != nil {
		return "", err
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
