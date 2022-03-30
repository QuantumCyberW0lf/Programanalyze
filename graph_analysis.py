#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class DiGraph:

    def __init__(self):
        # nodes in the graph
        self.nodes = set()
        # edges in the graph
        self.edges = set()
        # successors of a node
        self.successors = {}
        # predecessors of a node
        self.predecessors = {}

    def add_node(self, node):
        self.nodes.add(node)
        self.successors[node] = []
        self.predecessors[node] = []

    def add_edge(self, src, dst):
        if not src in self.nodes:
            self.add_node(src)
        if not dst in self.nodes:
            self.add_node(dst)
        self.edges.add((src, dst))
        self.successors[src].append(dst)
        self.predecessors[dst].append(src)

    def successors_iter(self, node):
        if not node in self.successors:
            return
        for successor in self.successors[node]:
            yield successor

    def predecessors_iter(self, node):
        if not node in self.predecessors:
            return
        for predecessor in self.predecessors[node]:
            yield predecessor
    
    def dot(self):
        ret = ["digraph { \n"]
        for (a, b) in self.edges:
            ret.append("{} -> {}\n".format(str(a), str(b)))
        ret.append("}\n")
        return ''.join(ret)

    def dump_dot(self, file_path):
        open(file_path, "wb").write(self.dot())
    
    def _walk_generic_first(self, head, flag, successors):
        """
        Generic algorithm to compute BFS/DFS
        for a node.
        @head: the head of the graph
        @flag: denotes if @todo is used as queue or stack
        @succ_cb: returns a node's predecessors/successors
        :return: next node
        """
        todo = [head]
        done = set()

        while todo:
            node = todo.pop(flag)
            if node in done:
                continue
            done.add(node)

            for successor in successors(node):
                todo.append(successor)

            yield node

    def walk_breadth_first_forward(self, head):
        """BFS on the graph"""
        return self._walk_generic_first(head, 0, self.successors_iter)

    def walk_depth_first_forward(self, head):
        """DFS on the graph"""
        return self._walk_generic_first(head, -1, self.successors_iter)

    def walk_breadth_first_backward(self, head):
        """BFS on the reversed graph"""
        return self._walk_generic_first(head, 0, self.predecessors_iter)

    def walk_depth_first_backward(self, head):
        """DFS on the reversed graph"""
        return self._walk_generic_first(head, -1, self.predecessors_iter)

edges = [
    (1, 2),
    (1, 6),
    (2, 7),
    (2, 3),
    (3, 8),
    (3, 4),
    (4, 2),
    (4, 5),
    (5, 14),
    (5, 6),
    (6, 12),
    (6, 15),
    (7, 15),
    (7, 9),
    (8, 15),
    (8, 10),
    (9, 11),
    (9, 13),
    (10, 12),
    (10, 18),
    (11, 16),
    (11, 17),
    (12, 1),
    (12, 15),
    (13, 16),
    (13, 17),
    (14, 3),
    (14, 19),
    (15, 18),
    (15, 16),
    (16, 2),
    (16, 19),
    (17, 7),
    (17, 18),
    (19, 1),
    (19, 7),
]

g = DiGraph()

for a, b in edges:
    g.add_edge(a, b)

for node in g.walk_breadth_first_forward(1):
    print(node)


g.dump_dot("/tmp/foo.dot")
