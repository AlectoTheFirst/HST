import { useWorkspace } from "../workspace/WorkspaceContext";
/** The change-simulation workspace has a chat at the bottom and the Baseline and Predicted panes above. */

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAiContext, useAiPaneId } from "../ai/context";
import { stepAssessmentDraft } from "../ai/ResultCards";
import {
  baselineFromContext,
  latestBaseline,
  latestPredicted,
  latestServiceImpact,
  latestServiceImpactStep,
  resultSnapshot,
  unreadablePredicted,
} from "./assessImpact";
import { BaselinePane } from "./BaselinePane";
import { ChatPanel } from "./ChatPanel";
import { PredictedPane } from "./PredictedPane";
import { ServiceImpactPane } from "./ServiceImpactPane";
import { useChangeSimChat } from "./useChangeSimChat";
import "./changesim.css";

export default function ChangeSimPage({
  conversationId,
  onConversation,
}: {
  /** The pane's conversation; absent until the first question creates one. */
  conversationId?: string;
  /** Stores the id of a created conversation on the pane, or clears it. */
  onConversation?: (id: string | undefined) => void;
} = {}) {
  const chat = useChangeSimChat(conversationId, onConversation);
  const workspace = useWorkspace();
  const baseline = useMemo(
    () => baselineFromContext(chat.turns) ?? latestBaseline(chat.turns),
    [chat.turns],
  );
  const predicted = useMemo(() => latestPredicted(chat.turns), [chat.turns]);
  const unreadable = useMemo(() => unreadablePredicted(chat.turns), [chat.turns]);
  const serviceImpact = useMemo(() => latestServiceImpact(chat.turns), [chat.turns]);
  // the draft of the step the service pane shows, built by the server from the stored step
  const serviceStepId = useMemo(() => latestServiceImpactStep(chat.turns)?.id, [chat.turns]);
  const assessmentDraft = useQuery({
    queryKey: ["ai-step-assessment-draft", serviceStepId],
    queryFn: () => stepAssessmentDraft(serviceStepId!),
    enabled: !!workspace && !!serviceStepId,
    staleTime: Infinity,
  }).data;
  // the run the newest pane result was computed on, as the page default
  const snapshot = resultSnapshot(predicted) ?? resultSnapshot(baseline);
  useAiContext(useAiPaneId(), snapshot ? { snapshot: { id: snapshot, origin: "page-default" } } : null);

  return (
    <div className="chgsim-page">
      <div className="chgsim-compare">
        <BaselinePane result={baseline} />
        <PredictedPane result={predicted} unreadable={unreadable} />
      </div>
      {serviceImpact && (
        <div className="chgsim-compare">
          <ServiceImpactPane result={serviceImpact} />
          {workspace && assessmentDraft && <button type="button" onClick={() => workspace.openAssessments(undefined, undefined, assessmentDraft)}>Investigate evidence</button>}
        </div>
      )}
      <ChatPanel chat={chat} conversationId={conversationId} />
    </div>
  );
}
