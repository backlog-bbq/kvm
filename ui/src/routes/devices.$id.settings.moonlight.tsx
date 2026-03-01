import { useCallback, useEffect, useState } from "react";
import { LuTrash2 } from "react-icons/lu";

import { useJsonRpc, JsonRpcResponse } from "@hooks/useJsonRpc";
import { Button } from "@components/Button";
import Checkbox from "@components/Checkbox";
import { SettingsItem } from "@components/SettingsItem";
import { SettingsPageHeader } from "@components/SettingsPageheader";
import { ConfirmDialog } from "@components/ConfirmDialog";
import notifications from "@/notifications";

interface MoonlightState {
  enabled: boolean;
  pairedClients: string[];
}

export default function MoonlightSettingsRoute() {
  const { send } = useJsonRpc();
  const [state, setState] = useState<MoonlightState | null>(null);
  const [confirmUnpair, setConfirmUnpair] = useState<string | null>(null);

  const loadState = useCallback(() => {
    send("getMoonlightState", {}, (resp: JsonRpcResponse) => {
      if ("error" in resp) return;
      setState(resp.result as MoonlightState);
    });
  }, [send]);

  useEffect(() => {
    loadState();
  }, [loadState]);

  const handleToggleEnabled = (enabled: boolean) => {
    send("setMoonlightEnabled", { enabled }, (resp: JsonRpcResponse) => {
      if ("error" in resp) {
        notifications.error("Failed to update Moonlight setting");
        return;
      }
      setState(prev => (prev ? { ...prev, enabled } : null));
      notifications.success(
        enabled
          ? "Moonlight enabled — restart required to start the server"
          : "Moonlight disabled — restart to stop the server",
      );
    });
  };

  const handleUnpair = (uniqueID: string) => {
    send("unpairMoonlightClient", { uniqueID }, (resp: JsonRpcResponse) => {
      if ("error" in resp) {
        notifications.error("Failed to unpair client");
        return;
      }
      setState(prev =>
        prev
          ? { ...prev, pairedClients: prev.pairedClients.filter(id => id !== uniqueID) }
          : null,
      );
      notifications.success("Client unpaired");
    });
    setConfirmUnpair(null);
  };

  return (
    <div className="space-y-6">
      <SettingsPageHeader
        title="Moonlight"
        description="Stream JetKVM video and send inputs using the open-source Moonlight client."
      />

      <div className="space-y-4">
        <SettingsItem
          title="Enable Moonlight"
          description="Start the Moonlight-compatible streaming server on this device. A restart is required when enabling for the first time."
        >
          <Checkbox
            checked={state?.enabled ?? false}
            onChange={e => handleToggleEnabled(e.target.checked)}
          />
        </SettingsItem>
      </div>

      <div className="space-y-3">
        <div>
          <h3 className="text-base font-semibold text-black dark:text-white">Paired clients</h3>
          <p className="text-sm text-slate-700 dark:text-slate-300">
            Moonlight clients that have completed PIN pairing and are allowed to connect.
          </p>
        </div>

        {state === null ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">Loading…</p>
        ) : state.pairedClients.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">
            No paired clients yet. Open Moonlight on your device and add this JetKVM to pair.
          </p>
        ) : (
          <div className="divide-y divide-slate-200 rounded-md border border-slate-200 dark:divide-slate-700 dark:border-slate-700">
            {state.pairedClients.map(uid => (
              <div
                key={uid}
                className="flex items-center justify-between px-4 py-3"
              >
                <span className="font-mono text-sm text-slate-700 dark:text-slate-300">{uid}</span>
                <Button
                  size="SM"
                  theme="lightDanger"
                  text="Unpair"
                  LeadingIcon={LuTrash2}
                  onClick={() => setConfirmUnpair(uid)}
                />
              </div>
            ))}
          </div>
        )}
      </div>

      <ConfirmDialog
        open={confirmUnpair !== null}
        onClose={() => setConfirmUnpair(null)}
        title="Unpair Moonlight client?"
        description={
          <>
            The client <span className="font-mono text-sm">{confirmUnpair}</span> will need to
            re-pair before it can connect again.
          </>
        }
        variant="danger"
        confirmText="Unpair"
        onConfirm={() => confirmUnpair && handleUnpair(confirmUnpair)}
      />
    </div>
  );
}
