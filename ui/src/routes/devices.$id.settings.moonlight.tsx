import { useCallback, useEffect, useState } from "react";
import { LuTrash2 } from "react-icons/lu";

import { JsonRpcResponse, useJsonRpc } from "@hooks/useJsonRpc";
import { Button } from "@components/Button";
import Checkbox from "@components/Checkbox";
import { SettingsItem } from "@components/SettingsItem";
import { SettingsPageHeader } from "@components/SettingsPageheader";
import { ConfirmDialog } from "@components/ConfirmDialog";
import { FieldError } from "@components/InputField";
import notifications from "@/notifications";

interface MoonlightState {
  enabled: boolean;
  pairedClients: string[];
}

export default function MoonlightSettingsRoute() {
  const { send } = useJsonRpc();
  const [state, setState] = useState<MoonlightState | null>(null);
  const [confirmUnpair, setConfirmUnpair] = useState<string | null>(null);

  // PIN entry state — always visible, not event-driven
  const [pin, setPin] = useState("");
  const [pinLoading, setPinLoading] = useState(false);
  const [pinError, setPinError] = useState<string | null>(null);

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

  const handlePinSubmit = useCallback(() => {
    if (pin.length !== 4) return;
    setPinError(null);
    setPinLoading(true);
    send(
      "submitMoonlightPIN",
      { uniqueID: "0123456789ABCDEF", pin },
      (resp: JsonRpcResponse) => {
        setPinLoading(false);
        if ("error" in resp) {
          setPinError(resp.error.data || resp.error.message || "Pairing failed");
        } else {
          setPin("");
          setPinError(null);
          loadState();
          notifications.success("Moonlight client paired successfully");
        }
      },
    );
  }, [pin, send, loadState]);

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
          <h3 className="text-base font-semibold text-black dark:text-white">Pair a client</h3>
          <p className="text-sm text-slate-700 dark:text-slate-300">
            Start pairing on your Moonlight client, then enter the 4-digit PIN it shows here.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={4}
            placeholder="0000"
            value={pin}
            onChange={e => {
              setPinError(null);
              setPin(e.target.value.replace(/\D/g, "").slice(0, 4));
            }}
            onKeyDown={e => {
              if (e.key === "Enter") handlePinSubmit();
            }}
            className="w-28 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-center text-lg tracking-[0.4em] text-slate-900 placeholder:tracking-normal placeholder:text-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none dark:border-slate-600 dark:bg-slate-800 dark:text-white dark:placeholder:text-slate-500"
          />
          <Button
            size="SM"
            theme="primary"
            text={pinLoading ? "Pairing\u2026" : "Pair"}
            onClick={handlePinSubmit}
            disabled={pin.length !== 4 || pinLoading}
          />
        </div>
        {pinError && <FieldError error={pinError} />}
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
