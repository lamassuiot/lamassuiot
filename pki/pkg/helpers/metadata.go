package helpers

import (
	"encoding/json"
)

func GetMetadataToStruct(metadata map[string]any, keyToGet string, elem any) (bool, error) {
	if iface, ok := metadata[keyToGet]; ok {
		//check if iface is of type
		ifaceB, err := json.Marshal(iface)
		if err != nil {
			return true, err
		}

		err = json.Unmarshal(ifaceB, &elem)
		if err != nil {
			return true, err
		}

		return true, nil
	} else {
		return false, nil
	}
}
