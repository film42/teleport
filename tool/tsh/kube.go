/*
Copyright 2020-2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gravitational/kingpin"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/profile"
	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/api/utils/keypaths"
	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/kube/kubeconfig"
	kubeutils "github.com/gravitational/teleport/lib/kube/utils"
	"github.com/gravitational/teleport/lib/srv/alpnproxy"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/pkg/apis/clientauthentication"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

type kubeCommands struct {
	credentials *kubeCredentialsCommand
	ls          *kubeLSCommand
	login       *kubeLoginCommand
	sessions    *kubeSessionsCommand
	exec        *kubeExecCommand
	join        *kubeJoinCommand
}

func newKubeCommand(app *kingpin.Application) kubeCommands {
	kube := app.Command("kube", "Manage available kubernetes clusters")
	cmds := kubeCommands{
		credentials: newKubeCredentialsCommand(kube),
		ls:          newKubeLSCommand(kube),
		login:       newKubeLoginCommand(kube),
		sessions:    newKubeSessionsCommand(kube),
		exec:        newKubeExecCommand(kube),
		join:        newKubeJoinCommand(kube),
	}
	return cmds
}

type kubeJoinCommand struct {
	*kingpin.CmdClause
	session  string
	mode     string
	siteName string
}

func newKubeJoinCommand(parent *kingpin.CmdClause) *kubeJoinCommand {
	c := &kubeJoinCommand{
		CmdClause: parent.Command("join", "Join an active Kubernetes session."),
	}

	c.Flag("mode", "Mode of joining the session, valid modes are observer and moderator").Short('m').Default("moderator").StringVar(&c.mode)
	c.Flag("cluster", clusterHelp).Short('c').StringVar(&c.siteName)
	c.Arg("session", "The ID of the target session.").Required().StringVar(&c.session)
	return c
}

func (c *kubeJoinCommand) getSessionMeta(ctx context.Context, tc *client.TeleportClient) (types.Session, error) {
	sessions, err := tc.GetActiveSessions(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for _, session := range sessions {
		if session.GetID() == c.session {
			return session, nil
		}
	}

	return nil, trace.NotFound("session %q not found", c.session)
}

func (c *kubeJoinCommand) run(cf *CLIConf) error {
	cf.SiteName = c.siteName
	tc, err := makeClient(cf, true)
	if err != nil {
		return trace.Wrap(err)
	}

	meta, err := c.getSessionMeta(cf.Context, tc)
	if err != nil {
		return trace.Wrap(err)
	}

	cluster := meta.GetClustername()
	kubeCluster := meta.GetKubeCluster()
	var k *client.Key

	// Try loading existing keys.
	k, err = tc.LocalAgent().GetKey(cluster, client.WithKubeCerts{})
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}

	// Loaded existing credentials and have a cert for this cluster? Return it
	// right away.
	if err == nil {
		crt, err := k.KubeTLSCertificate(kubeCluster)
		if err != nil && !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		if crt != nil && time.Until(crt.NotAfter) > time.Minute {
			log.Debugf("Re-using existing TLS cert for kubernetes cluster %q", kubeCluster)
		} else {
			err = client.RetryWithRelogin(cf.Context, tc, func() error {
				var err error
				k, err = tc.IssueUserCertsWithMFA(cf.Context, client.ReissueParams{
					RouteToCluster:    cluster,
					KubernetesCluster: kubeCluster,
				})

				return trace.Wrap(err)
			})

			if err != nil {
				return trace.Wrap(err)
			}

			// Cache the new cert on disk for reuse.
			if _, err := tc.LocalAgent().AddKey(k); err != nil {
				return trace.Wrap(err)
			}
		}
		// Otherwise, cert for this k8s cluster is missing or expired. Request
		// a new one.
	}

	if _, err := tc.Ping(cf.Context); err != nil {
		return trace.Wrap(err)
	}

	if tc.KubeProxyAddr == "" {
		// Kubernetes support disabled, don't touch kubeconfig.
		return trace.AccessDenied("this cluster does not support kubernetes")
	}

	kubeStatus, err := fetchKubeStatus(cf.Context, tc)
	if err != nil {
		return trace.Wrap(err)
	}

	session, err := client.NewKubeSession(cf.Context, tc, meta, k, tc.KubeProxyAddr, kubeStatus.tlsServerName, types.SessionParticipantMode(c.mode))
	if err != nil {
		return trace.Wrap(err)
	}

	session.Wait()
	return nil
}

func kubeExecCommandAssembler(c *kubeExecCommand) []string {
	var cmd []string
	cmd = append(cmd, "kubectl", "exec")
	if c.container != "" {
		cmd = append(cmd, "-c", c.container)
	}
	if c.filename != "" {
		cmd = append(cmd, "-f", c.filename)
	}
	if c.quiet {
		cmd = append(cmd, "-q")
	}
	if c.stdin {
		cmd = append(cmd, "-i")
	}
	if c.tty {
		cmd = append(cmd, "-t")
	}
	cmd = append(cmd, c.target, "--")
	cmd = append(cmd, c.command...)
	fmt.Println(cmd)
	return cmd
}

type kubeExecCommand struct {
	*kingpin.CmdClause
	target    string
	container string
	filename  string
	quiet     bool
	stdin     bool
	tty       bool
	reason    string
	invited   string
	command   []string
}

func newKubeExecCommand(parent *kingpin.CmdClause) *kubeExecCommand {
	c := &kubeExecCommand{
		CmdClause: parent.Command("exec", "Execute a command in a kubernetes pod"),
	}

	c.Flag("container", "Container name. If omitted, use the kubectl.kubernetes.io/default-container annotation for selecting the container to be attached or the first container in the pod will be chosen").Short('c').StringVar(&c.container)
	c.Flag("filename", "to use to exec into the resource").Short('f').StringVar(&c.filename)
	c.Flag("quiet", "Only print output from the remote session").Short('q').BoolVar(&c.quiet)
	c.Flag("stdin", "Pass stdin to the container").Short('s').BoolVar(&c.stdin)
	c.Flag("tty", "Stdin is a TTY").Short('t').BoolVar(&c.tty)
	c.Flag("reason", "The purpose of the session.").StringVar(&c.reason)
	c.Flag("invite", "A comma separated list of people to mark as invited for the session.").StringVar(&c.invited)
	c.Arg("target", "Pod or deployment name").Required().StringVar(&c.target)
	c.Arg("command", "Command to execute in the container").StringsVar(&c.command)
	return c
}

func (c *kubeExecCommand) run(cf *CLIConf) error {
	cmdStrings := kubeExecCommandAssembler(c)
	cmd := exec.Command(cmdStrings[0], cmdStrings[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return trace.Wrap(cmd.Run())
}

type kubeSessionsCommand struct {
	*kingpin.CmdClause
}

func newKubeSessionsCommand(parent *kingpin.CmdClause) *kubeSessionsCommand {
	c := &kubeSessionsCommand{
		CmdClause: parent.Command("sessions", "Get a list of active kubernetes sessions."),
	}

	return c
}

func (c *kubeSessionsCommand) run(cf *CLIConf) error {
	tc, err := makeClient(cf, true)
	if err != nil {
		return trace.Wrap(err)
	}

	sessions, err := tc.GetActiveSessions(cf.Context)
	if err != nil {
		return trace.Wrap(err)
	}

	filteredSessions := make([]types.Session, 0)
	for _, session := range sessions {
		if session.GetSessionKind() == types.KubernetesSessionKind {
			filteredSessions = append(filteredSessions, session)
		}
	}

	printSessions(filteredSessions)
	return nil
}

func printSessions(sessions []types.Session) {
	table := asciitable.MakeTable([]string{"ID", "State", "Created", "Hostname", "Address", "Login", "Reason"})
	for _, s := range sessions {
		table.AddRow([]string{s.GetID(), s.GetState().String(), s.GetCreated().Format(time.RFC3339), s.GetHostname(), s.GetAddress(), s.GetLogin(), s.GetReason()})
	}

	output := table.AsBuffer().String()
	print(output)
}

type kubeCredentialsCommand struct {
	*kingpin.CmdClause
	kubeCluster     string
	teleportCluster string
}

func newKubeCredentialsCommand(parent *kingpin.CmdClause) *kubeCredentialsCommand {
	c := &kubeCredentialsCommand{
		// This command is always hidden. It's called from the kubeconfig that
		// tsh generates and never by users directly.
		CmdClause: parent.Command("credentials", "Get credentials for kubectl access").Hidden(),
	}
	c.Flag("teleport-cluster", "Name of the teleport cluster to get credentials for.").Required().StringVar(&c.teleportCluster)
	c.Flag("kube-cluster", "Name of the kubernetes cluster to get credentials for.").Required().StringVar(&c.kubeCluster)
	return c
}

func (c *kubeCredentialsCommand) run(cf *CLIConf) error {
	tc, err := makeClient(cf, true)
	if err != nil {
		return trace.Wrap(err)
	}

	// Try loading existing keys.
	k, err := tc.LocalAgent().GetKey(c.teleportCluster, client.WithKubeCerts{})
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	// Loaded existing credentials and have a cert for this cluster? Return it
	// right away.
	if err == nil {
		crt, err := k.KubeTLSCertificate(c.kubeCluster)
		if err != nil && !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		if crt != nil && time.Until(crt.NotAfter) > time.Minute {
			log.Debugf("Re-using existing TLS cert for kubernetes cluster %q", c.kubeCluster)
			return c.writeResponse(k, c.kubeCluster)
		}
		// Otherwise, cert for this k8s cluster is missing or expired. Request
		// a new one.
	}

	log.Debugf("Requesting TLS cert for kubernetes cluster %q", c.kubeCluster)
	err = client.RetryWithRelogin(cf.Context, tc, func() error {
		var err error
		k, err = tc.IssueUserCertsWithMFA(cf.Context, client.ReissueParams{
			RouteToCluster:    c.teleportCluster,
			KubernetesCluster: c.kubeCluster,
		})
		return err
	})
	if err != nil {
		return trace.Wrap(err)
	}

	// Cache the new cert on disk for reuse.
	if _, err := tc.LocalAgent().AddKey(k); err != nil {
		return trace.Wrap(err)
	}

	return c.writeResponse(k, c.kubeCluster)
}

func (c *kubeCredentialsCommand) writeResponse(key *client.Key, kubeClusterName string) error {
	crt, err := key.KubeTLSCertificate(kubeClusterName)
	if err != nil {
		return trace.Wrap(err)
	}
	expiry := crt.NotAfter
	// Indicate slightly earlier expiration to avoid the cert expiring
	// mid-request, if possible.
	if time.Until(expiry) > time.Minute {
		expiry = expiry.Add(-1 * time.Minute)
	}
	resp := &clientauthentication.ExecCredential{
		Status: &clientauthentication.ExecCredentialStatus{
			ExpirationTimestamp:   &metav1.Time{Time: expiry},
			ClientCertificateData: string(key.KubeTLSCerts[kubeClusterName]),
			ClientKeyData:         string(key.Priv),
		},
	}
	data, err := runtime.Encode(kubeCodecs.LegacyCodec(kubeGroupVersion), resp)
	if err != nil {
		return trace.Wrap(err)
	}
	fmt.Println(string(data))
	return nil
}

type kubeLSCommand struct {
	*kingpin.CmdClause
}

func newKubeLSCommand(parent *kingpin.CmdClause) *kubeLSCommand {
	c := &kubeLSCommand{
		CmdClause: parent.Command("ls", "Get a list of kubernetes clusters"),
	}
	return c
}

func (c *kubeLSCommand) run(cf *CLIConf) error {
	tc, err := makeClient(cf, true)
	if err != nil {
		return trace.Wrap(err)
	}
	currentTeleportCluster, kubeClusters, err := fetchKubeClusters(cf.Context, tc)
	if err != nil {
		return trace.Wrap(err)
	}

	selectedCluster := selectedKubeCluster(currentTeleportCluster)

	var t asciitable.Table
	if cf.Quiet {
		t = asciitable.MakeHeadlessTable(2)
	} else {
		t = asciitable.MakeTable([]string{"Kube Cluster Name", "Selected"})
	}
	for _, cluster := range kubeClusters {
		var selectedMark string
		if cluster == selectedCluster {
			selectedMark = "*"
		}
		t.AddRow([]string{cluster, selectedMark})
	}
	fmt.Println(t.AsBuffer().String())

	return nil
}

func selectedKubeCluster(currentTeleportCluster string) string {
	kc, err := kubeconfig.Load("")
	if err != nil {
		log.WithError(err).Warning("Failed parsing existing kubeconfig")
		return ""
	}
	return kubeconfig.KubeClusterFromContext(kc.CurrentContext, currentTeleportCluster)
}

type kubeLoginCommand struct {
	*kingpin.CmdClause
	kubeCluster string
}

func newKubeLoginCommand(parent *kingpin.CmdClause) *kubeLoginCommand {
	c := &kubeLoginCommand{
		CmdClause: parent.Command("login", "Login to a kubernetes cluster"),
	}
	c.Arg("kube-cluster", "Name of the kubernetes cluster to login to. Check 'tsh kube ls' for a list of available clusters.").Required().StringVar(&c.kubeCluster)
	return c
}

func (c *kubeLoginCommand) run(cf *CLIConf) error {
	// Set CLIConf.KubernetesCluster so that the kube cluster's context is automatically selected.
	cf.KubernetesCluster = c.kubeCluster

	tc, err := makeClient(cf, true)
	if err != nil {
		return trace.Wrap(err)
	}
	// Check that this kube cluster exists.
	currentTeleportCluster, kubeClusters, err := fetchKubeClusters(cf.Context, tc)
	if err != nil {
		return trace.Wrap(err)
	}
	if !apiutils.SliceContainsStr(kubeClusters, c.kubeCluster) {
		return trace.NotFound("kubernetes cluster %q not found, check 'tsh kube ls' for a list of known clusters", c.kubeCluster)
	}

	// Try updating the active kubeconfig context.
	if err := kubeconfig.SelectContext(currentTeleportCluster, c.kubeCluster); err != nil {
		if !trace.IsNotFound(err) {
			return trace.Wrap(err)
		}
		// We know that this kube cluster exists from the API, but there isn't
		// a context for it in the current kubeconfig. This is probably a new
		// cluster, added after the last 'tsh login'.
		//
		// Re-generate kubeconfig contexts and try selecting this kube cluster
		// again.
		if err := updateKubeConfig(cf, tc, ""); err != nil {
			return trace.Wrap(err)
		}
	}

	// Generate a profile specific kubeconfig which can be used
	// by setting the kubeconfig environment variable (with `tsh env`)
	profileKubeconfigPath := keypaths.KubeConfigPath(
		profile.FullProfilePath(cf.HomePath), tc.WebProxyHost(), tc.Username, currentTeleportCluster, c.kubeCluster,
	)
	if err := updateKubeConfig(cf, tc, profileKubeconfigPath); err != nil {
		return trace.Wrap(err)
	}

	fmt.Printf("Logged into kubernetes cluster %q\n", c.kubeCluster)
	return nil
}

func fetchKubeClusters(ctx context.Context, tc *client.TeleportClient) (teleportCluster string, kubeClusters []string, err error) {
	err = client.RetryWithRelogin(ctx, tc, func() error {
		pc, err := tc.ConnectToProxy(ctx)
		if err != nil {
			return trace.Wrap(err)
		}
		defer pc.Close()
		ac, err := pc.ConnectToCurrentCluster(ctx, true)
		if err != nil {
			return trace.Wrap(err)
		}
		defer ac.Close()

		cn, err := ac.GetClusterName()
		if err != nil {
			return trace.Wrap(err)
		}
		teleportCluster = cn.GetClusterName()

		kubeClusters, err = kubeutils.KubeClusterNames(ctx, ac)
		if err != nil {
			return trace.Wrap(err)
		}
		return nil
	})
	if err != nil {
		return "", nil, trace.Wrap(err)
	}
	return teleportCluster, kubeClusters, nil
}

// kubernetesStatus holds teleport client information necessary to populate the user's kubeconfig.
type kubernetesStatus struct {
	clusterAddr         string
	teleportClusterName string
	kubeClusters        []string
	credentials         *client.Key
	tlsServerName       string
}

// fetchKubeStatus returns a kubernetesStatus populated from the given TeleportClient.
func fetchKubeStatus(ctx context.Context, tc *client.TeleportClient) (*kubernetesStatus, error) {
	var err error
	kubeStatus := &kubernetesStatus{
		clusterAddr: tc.KubeClusterAddr(),
	}
	kubeStatus.credentials, err = tc.LocalAgent().GetCoreKey()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	kubeStatus.teleportClusterName, kubeStatus.kubeClusters, err = fetchKubeClusters(ctx, tc)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if tc.TLSRoutingEnabled {
		kubeStatus.tlsServerName = getKubeTLSServerName(tc)
	}

	return kubeStatus, nil
}

// getKubeTLSServerName returns k8s server name used in KUBECONFIG to leverage TLS Routing.
func getKubeTLSServerName(tc *client.TeleportClient) string {
	k8host, _ := tc.KubeProxyHostPort()

	isIPFormat := net.ParseIP(k8host) != nil
	if k8host == "" || isIPFormat {
		// If proxy is configured without public_addr set the ServerName to the 'kube.teleport.cluster.local' value.
		// The k8s server name needs to be a valid hostname but when public_addr is missing from proxy settings
		// the web_listen_addr is used thus webHost will contain local proxy IP address like: 0.0.0.0 or 127.0.0.1
		return addSubdomainPrefix(constants.APIDomain, alpnproxy.KubeSNIPrefix)
	}
	return addSubdomainPrefix(k8host, alpnproxy.KubeSNIPrefix)
}

func addSubdomainPrefix(domain, prefix string) string {
	return fmt.Sprintf("%s.%s", prefix, domain)
}

// buildKubeConfigUpdate returns a kubeconfig.Values suitable for updating the user's kubeconfig
// based on the CLI parameters and the given kubernetesStatus.
func buildKubeConfigUpdate(cf *CLIConf, kubeStatus *kubernetesStatus) (*kubeconfig.Values, error) {
	v := &kubeconfig.Values{
		ClusterAddr:         kubeStatus.clusterAddr,
		TeleportClusterName: kubeStatus.teleportClusterName,
		Credentials:         kubeStatus.credentials,
		TLSServerName:       kubeStatus.tlsServerName,
	}

	if cf.executablePath == "" {
		// Don't know tsh path.
		// Fall back to the old kubeconfig, with static credentials from v.Credentials.
		return v, nil
	}

	if len(kubeStatus.kubeClusters) == 0 {
		// If there are no registered k8s clusters, we may have an older teleport cluster.
		// Fall back to the old kubeconfig, with static credentials from v.Credentials.
		log.Debug("Disabling exec plugin mode for kubeconfig because this Teleport cluster has no Kubernetes clusters.")
		return v, nil
	}

	v.Exec = &kubeconfig.ExecValues{
		TshBinaryPath:     cf.executablePath,
		TshBinaryInsecure: cf.InsecureSkipVerify,
		KubeClusters:      kubeStatus.kubeClusters,
		Env:               make(map[string]string),
	}

	if cf.HomePath != "" {
		v.Exec.Env[homeEnvVar] = cf.HomePath
	}

	// Only switch the current context if kube-cluster is explicitly set on the command line.
	if cf.KubernetesCluster != "" {
		if !apiutils.SliceContainsStr(kubeStatus.kubeClusters, cf.KubernetesCluster) {
			return nil, trace.BadParameter("Kubernetes cluster %q is not registered in this Teleport cluster; you can list registered Kubernetes clusters using 'tsh kube ls'.", cf.KubernetesCluster)
		}
		v.Exec.SelectCluster = cf.KubernetesCluster
	}
	return v, nil
}

// updateKubeConfig adds Teleport configuration to the users's kubeconfig based on the CLI
// parameters and the kubernetes services in the current Teleport cluster. If no path for
// the kubeconfig is given, it will use environment values or known defaults to get a path.
func updateKubeConfig(cf *CLIConf, tc *client.TeleportClient, path string) error {
	// Fetch proxy's advertised ports to check for k8s support.
	if _, err := tc.Ping(cf.Context); err != nil {
		return trace.Wrap(err)
	}
	if tc.KubeProxyAddr == "" {
		// Kubernetes support disabled, don't touch kubeconfig.
		return nil
	}

	kubeStatus, err := fetchKubeStatus(cf.Context, tc)
	if err != nil {
		return trace.Wrap(err)
	}

	values, err := buildKubeConfigUpdate(cf, kubeStatus)
	if err != nil {
		return trace.Wrap(err)
	}

	if path == "" {
		path = kubeconfig.PathFromEnv()
	}

	// If this is a profile specific kubeconfig, we only need
	// to put the selected kube cluster into the kubeconfig.
	isKubeConfig, err := keypaths.IsProfileKubeConfigPath(path)
	if err != nil {
		return trace.Wrap(err)
	}
	if isKubeConfig {
		if !strings.Contains(path, cf.KubernetesCluster) {
			return trace.BadParameter("profile specific kubeconfig is in use, run 'eval $(tsh env --unset)' to switch contexts to another kube cluster")
		}
		values.Exec.KubeClusters = []string{cf.KubernetesCluster}
	}

	return trace.Wrap(kubeconfig.Update(path, *values))
}

// Required magic boilerplate to use the k8s encoder.

var (
	kubeScheme       = runtime.NewScheme()
	kubeCodecs       = serializer.NewCodecFactory(kubeScheme)
	kubeGroupVersion = schema.GroupVersion{
		Group:   "client.authentication.k8s.io",
		Version: "v1beta1",
	}
)

func init() {
	metav1.AddToGroupVersion(kubeScheme, schema.GroupVersion{Version: "v1"})
	clientauthv1beta1.AddToScheme(kubeScheme)
	clientauthentication.AddToScheme(kubeScheme)
}
