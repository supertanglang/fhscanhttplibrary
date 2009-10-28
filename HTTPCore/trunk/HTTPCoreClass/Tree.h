#ifndef _TREE__H_
#define _TREE__H_




class TreeNode 
{

	char		   *text;
	int				count;
	class TreeNode *left;
	class TreeNode *right;
	class TreeNode *ParentItem;

	class bTree	   *ParentTree;
	class bTree    *ChildTree;
	void 		   *data;


public:

	TreeNode();
	TreeNode(const char *lpTreeNodeName);
	TreeNode(const char *lpTreeNodeName,TreeNode *Parent);
	~TreeNode();

	void SetTreeNodeName(const char *lpTreeNodeName);
	char *GetTreeNodeName(void) { return (text); };
	
	void SetTreeNodeCount(const int n) { count=n; }
	int GetTreeNodeCount(void) { return (count); }

	void SetTreeNodeLeft(TreeNode *newleft);
	class TreeNode*	GetTreeNodeLeft(void) { return (left); }

	void SetTreeNodeRight(TreeNode *newright);
	class TreeNode*	GetTreeNodeRight(void) { return (right); }
	
	void SetTreeNodeParentItem (TreeNode *Parent) { ParentItem = Parent; }
	class TreeNode * GetTreeNodeParentItem(void) { return ParentItem; }
	class TreeNode * GetTreeNodeParentItemTop(void);

	void SetTreeNodeParentTree( class bTree *ptree) {ParentTree = ptree;}
	class bTree * GetTreeNodeParentTree(void) {return ParentTree;}

	void SetTreeNodeChildTree(bTree *SubTree) { ChildTree = SubTree; }
	class bTree *GetTreeNodeChildTree(void) { return (ChildTree); }
	
	void SetData(void *ptr) { data = ptr; }
	void *GetData(void) { return data ; }

	
	class bTree* GetNewTreeNodeSubTree(void);
	class bTree* GetNewTreeNodeSubTree(char *lpSubTree);
	class TreeNode	*GetTreeNodeItemID(int n);

};


class bTree {
private:
	char *text;
	TreeNode *root;
	int count;
public:
	bTree();
	bTree(char *lpTreeName);
	~bTree();
	void		SetTreeName(const char *lpTreeName);
	int			GetCount() { return (count); }
	TreeNode	*TreeExistItem(const char *lpTreeItemName);
	TreeNode	*GetTreeNodeItemID(int n);
	TreeNode	*TreeInsert(const char *str,TreeNode *ParentItem);
	TreeNode	*TreeInsert(const char *str);

	void SubTreePrint(TreeNode *subtree);
	void TreePrint();
};

#endif