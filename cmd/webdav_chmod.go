package cmd

import (
	"bytes"
	"encoding/xml"
	"errors"
	"net/http"
	"os"
	"path"

	"golang.org/x/net/webdav"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// executableProp is the property WebDAV carries a file's execute permission
// in: "T" or "F", defined by Apache mod_dav and what davfs2 reads on PROPFIND
// and writes on chmod. WebDAV has no property for the rest of a POSIX mode, so
// the execute bits are all a mounted client can read or change.
var executableProp = xml.Name{Space: "http://apache.org/dav/props/", Local: "executable"}

// DeadProps implements webdav.DeadPropsHolder: a file reports whether its
// stored mode makes it executable.
func (h *readFileHandle) DeadProps() (map[xml.Name]webdav.Property, error) {
	value := "F"
	if h.info.Mode()&0111 != 0 {
		value = "T"
	}

	return map[xml.Name]webdav.Property{
		executableProp: {XMLName: executableProp, InnerXML: []byte(value)},
	}, nil
}

// Patch implements webdav.DeadPropsHolder. PROPPATCH opens its target for
// writing, so this handle never receives one.
func (h *readFileHandle) Patch(patches []webdav.Proppatch) ([]webdav.Propstat, error) {
	return forbidPatches(patches, nil), nil
}

// DeadProps implements webdav.DeadPropsHolder; properties are read through
// the read handle.
func (h *writeFileHandle) DeadProps() (map[xml.Name]webdav.Property, error) { return nil, nil }

// Patch implements webdav.DeadPropsHolder: x/net/webdav opens the target of a
// PROPPATCH for writing, so this handle is where a chmod arrives. Setting the
// executable property changes the execute bits of the node's stored mode
// (vfs.FS.SetExecutable: no new version, the cached listing updated in place);
// every other property is refused.
func (h *writeFileHandle) Patch(patches []webdav.Proppatch) ([]webdav.Propstat, error) {
	executable, ok := executablePatch(patches)
	if !ok {
		return forbidPatches(patches, func(name xml.Name) bool { return name == executableProp }), nil
	}
	err := h.wfs.tree.SetExecutable(h.ctx, h.drID, path.Join(h.parentPath, h.fileName), executable)
	switch {
	case err == nil:
		return executablePropstat(http.StatusOK), nil
	case errors.Is(err, vfs.ErrIsDir):
		return forbidPatches(patches, nil), nil
	case errors.Is(err, api.ErrLocked):
		return executablePropstat(webdav.StatusLocked), nil
	case errors.Is(err, vfs.ErrNotExist):
		// Nothing under that name, or a node deleted elsewhere since it was
		// listed.
		return nil, os.ErrNotExist
	case errors.Is(err, vfs.ErrForbidden):
		return executablePropstat(http.StatusForbidden), nil
	default:
		return nil, err
	}
}

// executablePatch reports the value a PROPPATCH gives the executable
// property, and whether it sets nothing else. Removing the property clears
// the execute bits.
func executablePatch(patches []webdav.Proppatch) (executable, ok bool) {
	for _, patch := range patches {
		for _, p := range patch.Props {
			if p.XMLName != executableProp {
				return false, false
			}
			switch value := string(bytes.TrimSpace(p.InnerXML)); {
			case patch.Remove, value == "F":
				executable = false
			case value == "T":
				executable = true
			default:
				return false, false
			}
			ok = true
		}
	}

	return executable, ok
}

func executablePropstat(status int) []webdav.Propstat {
	return []webdav.Propstat{{Status: status, Props: []webdav.Property{{XMLName: executableProp}}}}
}

// forbidPatches refuses a PROPPATCH: 403 on its properties, and 424 on those
// dependent reports as writable, which were not applied because of the others
// (RFC 4918 §9.2: a PROPPATCH applies all its instructions or none).
func forbidPatches(patches []webdav.Proppatch, dependent func(xml.Name) bool) []webdav.Propstat {
	forbidden := webdav.Propstat{Status: http.StatusForbidden}
	failed := webdav.Propstat{Status: webdav.StatusFailedDependency}
	for _, patch := range patches {
		for _, p := range patch.Props {
			if dependent != nil && dependent(p.XMLName) {
				failed.Props = append(failed.Props, webdav.Property{XMLName: p.XMLName})

				continue
			}
			forbidden.Props = append(forbidden.Props, webdav.Property{XMLName: p.XMLName})
		}
	}
	pstats := make([]webdav.Propstat, 0, 2)
	for _, pstat := range []webdav.Propstat{forbidden, failed} {
		if len(pstat.Props) > 0 {
			pstats = append(pstats, pstat)
		}
	}

	return pstats
}

var (
	_ webdav.DeadPropsHolder = (*readFileHandle)(nil)
	_ webdav.DeadPropsHolder = (*writeFileHandle)(nil)
)
