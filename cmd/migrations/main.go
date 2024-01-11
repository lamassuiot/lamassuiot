package main

import (
	"fmt"
	"strings"
)

func main() {
	list := MigrationList{}

	list.add("2.3.0")
	list.add("2.3.1")
	list.add("2.4.0")
	list.add("2.4.1")
	list.add("2.4.2")
	list.add("2.4.3")
	list.add("2.4.4")
	list.add("2.4.5")
	list.add("2.5.X")

	//Check the functionality of the get node id
	_, err := list.GetNodeId(3)
	if err != nil {
		panic(err)
	}

	//Check the functionality of the get node version
	_, err = list.GetNodeVersion("2.4.2")
	if err != nil {
		panic(err)
	}

	//Check the  functionality of the traverse

	listNodes, err := list.Traverse("2.4.5", "2.4.0")
	if err != nil {
		panic(err)
	}

	nIDs := []string{}
	for _, n := range listNodes {
		nIDs = append(nIDs, n.versionId)
	}

	if len(listNodes) > 0 {
		n0 := listNodes[0]
		nLast := listNodes[len(nIDs)-1]
		updateMode := "Forward Update"
		if n0.id > nLast.id {
			updateMode = "Rollback Update"
		}

		migrationVersionSequence := strings.Join(nIDs, " -> ")
		fmt.Printf("%s: %s\n", updateMode, migrationVersionSequence)
	}

	//Check the functionality of the get until tail

	// fmt.Println()

	// fmt.Println()
	// fmt.Println("checking the functionality of the getting until tail")

	// listNoT, err := list.GetUntilTail("2.4.5")
	// if err != nil {
	// 	panic(err)
	// }
	// for cont < len(listNoT) {
	// 	fmt.Println()
	// 	fmt.Printf("This is the node verdionId %s and its id %d", listNoT[cont].versionId, listNoT[cont].id)
	// 	cont = cont + 1
	// }
	// cont = 0

	// //Check the functionality of the get until head

	// fmt.Println()
	// fmt.Println("checking the functionality of the getting until head")

	// listNoH, err := list.GettinUntilHead("2.4.0")
	// if err != nil {
	// 	panic(err)
	// }
	// for cont < len(listNoH) {
	// 	fmt.Println()
	// 	fmt.Printf("This is the node verdionId %s and its id %d", listNoH[cont].versionId, listNoH[cont].id)
	// 	cont = cont + 1
	// }
	// cont = 0

	//////////////////// THE PART OF CHECKING THE LIST FUNCTIONALITIESS

}

type MigrationNode struct {
	id        int
	versionId string
	next      *MigrationNode
	prev      *MigrationNode
}

type MigrationList struct {
	tail   *MigrationNode
	head   *MigrationNode
	length int
}

func (l *MigrationList) add(id string) *MigrationNode {
	newNode := &MigrationNode{versionId: id}

	if l.head == nil {
		newNode.id = 0

		l.head = newNode
		l.tail = newNode
		l.length = 1
		return newNode
	}

	curr := l.head

	curr.next = newNode
	newNode.prev = curr
	newNode.id = l.length
	l.length = l.length + 1
	l.head = newNode
	return newNode
}

func (l *MigrationList) GetNodeId(id int) (*MigrationNode, error) {
	//Aqui se ha modificado de head to tail -> habra que empezar la lista desde el ultimo bloque no? si hacemos un next por lo menos luego
	curr := l.tail
	for curr != nil {
		if curr.id == id {
			return curr, nil
		}
		curr = curr.next
	}

	return nil, fmt.Errorf("The node id has not been found in the list: %d", id)
}

func (l *MigrationList) GetNodeVersion(versionId string) (*MigrationNode, error) {
	curr := l.tail
	for curr != nil {
		if curr.versionId == versionId {
			return curr, nil
		}
		curr = curr.next
	}

	return nil, fmt.Errorf("The node versionId has not been found in the list: %s", versionId)
}

// NodeLists
func (l *MigrationList) Traverse(fromVersionID string, toVersionID string) ([]*MigrationNode, error) {
	var listN []*MigrationNode

	nodeFrom, err := l.GetNodeVersion(fromVersionID)
	if err != nil {
		return nil, fmt.Errorf("node %s not in the list", fromVersionID)
	}

	nodeTo, err := l.GetNodeVersion(toVersionID)
	if err != nil {
		return nil, fmt.Errorf("node %s not in the list", fromVersionID)
	}

	if nodeFrom.id != nodeTo.id {
		var getNext func(node *MigrationNode) *MigrationNode
		curr := nodeFrom

		if nodeFrom.id < nodeTo.id {
			//forward
			getNext = func(node *MigrationNode) *MigrationNode { return node.next }
			curr = getNext(nodeFrom)
		} else if nodeFrom.id > nodeTo.id {
			//rolleback
			getNext = func(node *MigrationNode) *MigrationNode { return node.prev }
			nodeTo = nodeTo.next
		}

		for curr != nil {
			listN = append(listN, curr)
			if curr.id == nodeTo.id {
				return listN, nil
			}

			curr = getNext(curr)
		}

		return nil, fmt.Errorf("target node not found")
	}

	return listN, nil
}

// NodeLists
func (l *MigrationList) GetUntilTail(fromVersionID string) ([]*MigrationNode, error) {

	var listN []*MigrationNode

	nodeF, err := l.GetNodeVersion(fromVersionID)

	if err != nil {
		return nil, fmt.Errorf("The node versionId has not been found in the list: %s", fromVersionID)
	}

	curr := nodeF

	for curr != nil {
		nodeA, err := l.GetNodeId(curr.id)
		if err != nil {
			return nil, fmt.Errorf("The node versionId has not been found in the list: %s", fromVersionID)
		}
		fmt.Println("This node has been added to the list, with the following versionID ->  %s", nodeA.versionId)
		listN = append(listN, nodeA)
		curr = curr.prev
	}

	return listN, nil
}

// NodeLists
func (l *MigrationList) GettingUntilHead(fromVersionID string) ([]*MigrationNode, error) {

	var listN []*MigrationNode

	nodeF, err := l.GetNodeVersion(fromVersionID)

	if err != nil {
		return nil, fmt.Errorf("The node versionId has not been found in the list: %s", fromVersionID)
	}

	curr := nodeF

	fmt.Println(curr.next.versionId)

	for curr != nil {
		nodeA, err := l.GetNodeId(curr.id)
		if err != nil {
			return nil, fmt.Errorf("The node versionId has not been found in the list: %s", fromVersionID)
		}
		fmt.Println("This node has been added to the list, with the following versionID ->  %s", nodeA.versionId)
		listN = append(listN, nodeA)
		curr = curr.next
	}

	return listN, nil
}
