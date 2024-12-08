package hunting_sideload

import (
	"context"
	"fmt"
	"github.com/Velocidex/ordereddict"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	vfilter "www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
	"www.velocidex.com/golang/vfilter/types"
)

type CheckDLLArgs struct {
	DLLName      string `vfilter:"required,field=dll_name,doc=Name of the DLL"`
	DLLPath      string `vfilter:"required,field=dll_path,doc=Path to the DLL"`
	YAMLFolder   string `vfilter:"required,field=yaml_folder,doc=Path to folder containing YAML files"`
	SigcheckPath string `vfilter:"optional,field=sigcheck_path,doc=Path to sigcheck.exe"`
}

type MaliciousDll struct {
	Name string `json:"name"`
	Path string `json:"path"`
	MD5  string `json:"md5"`
}

type VertifyDLLPlugin struct{}

func (self VertifyDLLPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:    "vertify_dll_plugin",
		Doc:     "Check file signature using Sysinternals Sigcheck",
		ArgType: type_map.AddType(scope, &SigCheckArgs{}),
	}
}

func (self VertifyDLLPlugin) Call(
	ctx context.Context,
	scope vfilter.Scope,
	args *ordereddict.Dict) <-chan types.Row {

	output_chan := make(chan types.Row)

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor("check_dll_sideload", args)()

		arg := &CheckDLLArgs{}
		err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("check_dll_sideload: %s", err.Error())
			return
		}

		filesign_args := ordereddict.NewDict().
			Set("file_path", "C:\\Windows\\Temp")

		sigcheck := &SigCheckPlugin{}

		//var signatureResults []SignatureInfo
		rows := []types.Row{}
		for row := range sigcheck.Call(ctx, scope, filesign_args) {
			rows = append(rows, row)
		}

		var signatureResults []SignatureInfo
		for _, result := range rows {
			dict := result.(*ordereddict.Dict)
			signatureInfo := SignatureInfo{
				Name:        toString(dict.Get("name")),
				Verified:    toString(dict.Get("verified")),
				Publisher:   toString(dict.Get("publisher")),
				Company:     toString(dict.Get("company")),
				Description: toString(dict.Get("description")),
				ProductName: toString(dict.Get("product_name")),
				FileVersion: toString(dict.Get("file_version")),
				FileDate:    toString(dict.Get("file_date")),
				MD5:         toString(dict.Get("md5")),
				SHA1:        toString(dict.Get("sha1")),
				PESHA1:      toString(dict.Get("pe_sha1")),
			}

			signatureResults = append(signatureResults, signatureInfo)
		}
		result := ""
		select {
		case <-ctx.Done():
			return
		case output_chan <- result:
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&VertifyDLLPlugin{})
}

func toString(value interface{}, ok bool) string {
	if !ok || value == nil {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", value)
}
