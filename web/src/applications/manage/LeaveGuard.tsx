import { useContext, useEffect, type RefObject } from "react";
import { UNSAFE_DataRouterContext, useBlocker } from "react-router";
import { ConfirmDialog } from "../../inventory/ui/Page";

/** A navigation to another path waits for Stay or Leave. */
function NavigationBlock({ allow }: { allow?: RefObject<boolean> }) {
  const blocker = useBlocker(
    ({ currentLocation, nextLocation }) =>
      !allow?.current && currentLocation.pathname !== nextLocation.pathname,
  );
  if (blocker.state !== "blocked") return null;
  return (
    <ConfirmDialog
      label="Unsaved changes"
      title="Unsaved changes"
      confirmLabel="Leave"
      cancelLabel="Stay"
      onConfirm={() => blocker.proceed()}
      onCancel={() => blocker.reset()}
    >
      {null}
    </ConfirmDialog>
  );
}

/** While `when` holds, the browser asks before it unloads the page, and a
 *  navigation to another path waits for Stay or Leave. A true `allow` lets a
 *  navigation pass. Under a router without data, only the unload prompt applies. */
export function LeaveGuard({ when, allow }: { when: boolean; allow?: RefObject<boolean> }) {
  const dataRouter = useContext(UNSAFE_DataRouterContext);
  useEffect(() => {
    if (!when) return;
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, [when]);
  return when && dataRouter ? <NavigationBlock allow={allow} /> : null;
}
