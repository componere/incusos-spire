package main

import (
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

// main serves the WorkloadAttestor plugin together with the Config service.
//
// The Config service is mandatory here: SPIRE fails to load a plugin that is
// declared with a plugin_data block but does not advertise it.
// [pluginmain.Serve] does not return; it exits the process on a serve failure.
func main() {
	plugin := new(Plugin)
	pluginmain.Serve(
		workloadattestorv1.WorkloadAttestorPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
