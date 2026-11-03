# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from unittest import TestCase

from ..models import DBID, IssueInstance, SourceLocation, TraceFrameAnnotation
from ..trace_graph import TraceGraph
from ..trimmed_trace_graph import TrimmedTraceGraph
from .fake_object_generator import FakeObjectGenerator


class TraceGraphTest(TestCase):
    def test_annotation_lookup_after_updates(self) -> None:
        graph = TraceGraph()
        annotation = TraceFrameAnnotation.Record(
            id=DBID(),
            trace_frame_id=DBID(),
            location=SourceLocation(1, 1, 1),
            message="original",
            kind=None,
            leaf_id=None,
            link=None,
            trace_key=None,
        )
        graph.add_trace_annotation(annotation)
        frame_id = annotation.trace_frame_id.local_id
        self.assertEqual(graph.get_condition_annotations(frame_id), [annotation])
        graph.get_condition_annotations(frame_id).clear()
        self.assertEqual(graph.get_condition_annotations(frame_id), [annotation])

        replacement = TraceFrameAnnotation.Record(
            id=annotation.id,
            trace_frame_id=DBID(),
            location=annotation.location,
            message="replacement",
            kind=None,
            leaf_id=None,
            link=None,
            trace_key=None,
        )
        graph.add_trace_annotation(replacement)
        self.assertEqual(graph.get_condition_annotations(frame_id), [])
        self.assertEqual(
            graph.get_condition_annotations(replacement.trace_frame_id.local_id),
            [replacement],
        )

    def _populate_run(
        self,
        graph: TraceGraph,
        fakes: FakeObjectGenerator,
        run_id: DBID,
        index: int,
        affected_issues_only: bool,
        trace_filename: str = "affected.py",
    ) -> IssueInstance:
        sink = fakes.sink()
        issue = fakes.issue()
        instance = fakes.instance(
            issue_id=issue.id,
            run_id=run_id,
            filename="affected.py" if affected_issues_only else "issue.py",
            min_trace_length_to_sinks=2 - index,
        )
        graph.add_issue_instance_shared_text_assoc(instance, sink)
        root = fakes.precondition(
            caller="issue",
            caller_port="root",
            callee="shared",
            callee_port="argument(0)",
            filename=trace_filename,
            leaves=[(sink, 2 - index)],
            run_id=run_id,
        )
        graph.add_issue_instance_trace_frame_assoc(instance, root)
        fakes.precondition(
            caller="tail" if index == 0 else "shared",
            caller_port="argument(0)",
            callee_port="sink",
            leaves=[(sink, 0)],
            run_id=run_id,
        )
        if index == 0:
            fakes.precondition(
                caller="shared",
                caller_port="argument(0)",
                callee="tail",
                callee_port="argument(0)",
                leaves=[(sink, 1)],
                run_id=run_id,
            )
        fakes.class_type_interval(class_name=str(index), run_id=run_id)
        return instance

    def test_trimming_does_not_follow_other_runs(self) -> None:
        for affected_issues_only in (False, True):
            with self.subTest(affected_issues_only=affected_issues_only):
                graph = TraceGraph()
                fakes = FakeObjectGenerator(graph)
                run_ids = [DBID(), DBID()]
                instances = [
                    self._populate_run(
                        graph, fakes, run_id, index, affected_issues_only
                    )
                    for index, run_id in enumerate(run_ids)
                ]
                trimmed = TrimmedTraceGraph(
                    ["affected.py"], affected_issues_only, run_ids[0]
                )
                trimmed.populate_from_trace_graph(graph)
                self.assertEqual(list(trimmed.get_issue_instances()), instances[:1])
                self.assertEqual(instances[0].min_trace_length_to_sinks, 2)
                self.assertEqual(instances[0].callable_count, 1)
                self.assertEqual(instances[1].min_trace_length_to_sinks, 1)
                self.assertEqual(len(trimmed._trace_frames), 3)
                self.assertTrue(
                    all(
                        frame.run_id is run_ids[0]
                        for frame in trimmed._trace_frames.values()
                    )
                )
                self.assertEqual(set(trimmed._class_type_intervals), {"0"})
                self.assertEqual(set(graph._class_type_intervals), {"0", "1"})

    def test_trimming_without_run_selection_keeps_all_runs(self) -> None:
        graph = TraceGraph()
        fakes = FakeObjectGenerator(graph)
        for run_id in (DBID(), DBID()):
            issue = fakes.issue()
            fakes.instance(issue_id=issue.id, filename="affected.py", run_id=run_id)
        trimmed = TrimmedTraceGraph(["affected.py"])
        trimmed.populate_from_trace_graph(graph)
        self.assertEqual(len(list(trimmed.get_issue_instances())), 2)

    def test_affected_files_in_other_runs_do_not_select_issues(self) -> None:
        graph = TraceGraph()
        fakes = FakeObjectGenerator(graph)
        selected_run = DBID()
        self._populate_run(graph, fakes, selected_run, 0, False, "other.py")
        self._populate_run(graph, fakes, DBID(), 1, False)
        trimmed = TrimmedTraceGraph(["affected.py"], run_id=selected_run)
        trimmed.populate_from_trace_graph(graph)
        self.assertEqual(list(trimmed.get_issue_instances()), [])
        self.assertEqual(trimmed._trace_frames, {})
