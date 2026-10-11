package cmd

import (
	"bytes"
	"encoding/xml"
	"errors"
	"net/http"
	"os"

	"golang.org/x/net/webdav"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
)

// executableProp is the property WebDAV carries a file's execute permission
// in: "T" or "F", defined by Apache mod_dav and what davfs2 reads on PROPFIND
// and writes on chmod. WebDAV has no property for the rest of a POSIX mode, so
// the execute bits are all a mounted client can read or change.
var executableProp = xml.Name{Space: "http://apache.org/dav/props/", Local: "executable"}

// defaultFileMode is the mode of a file whose node stores none.
const defaultFileMode os.FileMode = 0644

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
// (PUT /dataroom/node/{id}, no new version); every other property is refused.
func (h *writeFileHandle) Patch(patches []webdav.Proppatch) ([]webdav.Propstat, error) {
	executable, ok := executablePatch(patches)
	if !ok {
		return forbidPatches(patches, func(name xml.Name) bool { return name == executableProp }), nil
	}
	node, err := h.wfs.findListedNode(h.ctx, h.drID, h.parentPath, h.fileName)
	if err != nil {
		return nil, err
	}
	if node.Type != "file" {
		return forbidPatches(patches, nil), nil
	}

	mode := withExecutable(node.Mode(), executable)
	if mode != node.Mode() {
		err := h.wfs.client.SetDataroomNodeAccessMode(h.ctx, node.ID, api.FormatAccessMode(mode))
		var httpErr *api.HTTPError
		switch {
		case errors.Is(err, api.ErrLocked):
			return executablePropstat(webdav.StatusLocked), nil
		case errors.Is(err, api.ErrNotFound):
			// The listing named a node deleted elsewhere.
			h.wfs.invalidateNodeCache(dataroomURI(h.drID, h.parentPath))

			return nil, os.ErrNotExist
		case errors.As(err, &httpErr) && httpErr.Status == http.StatusForbidden:
			return executablePropstat(http.StatusForbidden), nil
		case err != nil:
			return nil, err
		}
		h.wfs.upsertNodeCache(dataroomURI(h.drID, h.parentPath), node.WithMode(mode))
	}

	return executablePropstat(http.StatusOK), nil
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

// withExecutable returns mode with its execute bits set for whoever may read
// the file (what chmod +x gives under the usual umask), or cleared. A node
// without a stored mode starts from defaultFileMode.
func withExecutable(mode os.FileMode, executable bool) os.FileMode {
	if mode.Perm() == 0 {
		mode |= defaultFileMode
	}
	if !executable {
		return mode &^ 0111
	}

	return mode | 0100 | (mode&0444)>>2
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

// keepMode returns node with the mode of the cached entry it replaces when it
// carries none: an upload does not change a node's mode, and not every upload
// path learns it from the API.
func keepMode(node, cached service.DataroomNodeInfo) service.DataroomNodeInfo {
	if node.Mode() == 0 && node.ID == cached.ID {
		return node.WithMode(cached.Mode())
	}

	return node
}
