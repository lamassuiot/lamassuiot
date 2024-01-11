package storage

import "fmt"

type MigrationNode struct {
	id                    int
	versionId             string
	upgradeModelVersion   func() error
	downgradeModelVersion func() error
	next                  *MigrationNode
	prev                  *MigrationNode
}

type MigrationList struct {
	tail   *MigrationNode
	head   *MigrationNode
	length int
}

func (l *MigrationList) Add(versionID string, upgradeModelVersion func() error, downgradeModelVersion func() error) *MigrationNode {
	newNode := &MigrationNode{
		versionId:             versionID,
		upgradeModelVersion:   upgradeModelVersion,
		downgradeModelVersion: downgradeModelVersion,
	}

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
	curr := l.tail
	for curr != nil {
		if curr.id == id {
			return curr, nil
		}
		curr = curr.next
	}

	return nil, fmt.Errorf("node not been found: %d", id)
}

func (l *MigrationList) GetNodeVersion(versionId string) (*MigrationNode, error) {
	curr := l.tail
	for curr != nil {
		if curr.versionId == versionId {
			return curr, nil
		}
		curr = curr.next
	}

	return nil, fmt.Errorf("node not been found: %s", versionId)
}

type MigrationMode string

const (
	MigrationModeForward  MigrationMode = "FORWARD"
	MigrationModeRollback MigrationMode = "ROLLBACK"
)

// NodeLists
func (l *MigrationList) Traverse(fromVersionID string, toVersionID string) (MigrationMode, []*MigrationNode, error) {
	var listN []*MigrationNode

	nodeFrom, err := l.GetNodeVersion(fromVersionID)
	if err != nil {
		return MigrationModeForward, nil, fmt.Errorf("node %s not in the list", fromVersionID)
	}

	nodeTo, err := l.GetNodeVersion(toVersionID)
	if err != nil {
		return MigrationModeForward, nil, fmt.Errorf("node %s not in the list", fromVersionID)
	}

	if nodeFrom.id != nodeTo.id {
		var getNext func(node *MigrationNode) *MigrationNode
		curr := nodeFrom
		mode := MigrationModeForward

		if nodeFrom.id < nodeTo.id {
			//forward
			getNext = func(node *MigrationNode) *MigrationNode { return node.next }
			curr = getNext(nodeFrom)
		} else if nodeFrom.id > nodeTo.id {
			//rollback
			getNext = func(node *MigrationNode) *MigrationNode { return node.prev }
			nodeTo = nodeTo.next
			mode = MigrationModeRollback
		}

		for curr != nil {
			listN = append(listN, curr)
			if curr.id == nodeTo.id {
				return mode, listN, nil
			}

			curr = getNext(curr)
		}

		return MigrationModeForward, nil, fmt.Errorf("target node not found")
	}

	return MigrationModeForward, listN, nil
}

func ApplyMigration(migrationMode MigrationMode, nodeList []*MigrationNode) error {
	if migrationMode == MigrationModeForward {
		for _, node := range nodeList {
			err := node.upgradeModelVersion()
			if err != nil {
				return err
			}
		}
	} else {
		for _, node := range nodeList {
			err := node.downgradeModelVersion()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

type ModelMigrator[E any] struct {
}
