import { useCallback, useEffect, useRef, useState } from "react";

import { Button } from "@components/Button";
import Modal from "@components/Modal";
import { JsonRpcRequest, JsonRpcResponse, useJsonRpc } from "@hooks/useJsonRpc";
import notifications from "@/notifications";

interface PairingRequest {
  deviceName: string;
  uniqueID: string;
}

/**
 * MoonlightPINDialog appears automatically when the backend emits a
 * `moonlightPairingRequest` event (i.e. a Moonlight client has started
 * pairing). The user must type the 4-digit PIN shown on the Moonlight
 * client and submit it here so the server can derive the shared AES key.
 */
export default function MoonlightPINDialog() {
  const [request, setRequest] = useState<PairingRequest | null>(null);
  const [pin, setPin] = useState("");
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Receive the pairing request event from the backend.
  const onRpcRequest = useCallback((req: JsonRpcRequest) => {
    if (req.method === "moonlightPairingRequest") {
      const { deviceName, uniqueID } = req.params as unknown as PairingRequest;
      setRequest({ deviceName, uniqueID });
      setPin("");
      setLoading(false);
    }
  }, []);

  const { send } = useJsonRpc(onRpcRequest);

  // Focus the input when the dialog opens.
  useEffect(() => {
    if (request) {
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [request]);

  const handleClose = useCallback(() => {
    setRequest(null);
    setPin("");
    setLoading(false);
  }, []);

  const handleSubmit = useCallback(() => {
    if (!request || pin.length !== 4) return;
    setLoading(true);
    send(
      "submitMoonlightPIN",
      { uniqueID: request.uniqueID, pin },
      (resp: JsonRpcResponse) => {
        setLoading(false);
        if ("error" in resp) {
          notifications.error(`Pairing failed: ${resp.error.data || resp.error.message}`);
        } else {
          notifications.success("Moonlight pairing PIN submitted");
          handleClose();
        }
      },
    );
  }, [request, pin, send, handleClose]);

  if (!request) return null;

  return (
    <Modal open={true} onClose={handleClose}>
      <div className="w-full max-w-sm rounded-lg bg-white p-6 shadow-xl dark:bg-slate-800">
        <h2 className="mb-1 text-base font-semibold text-gray-900 dark:text-white">
          Moonlight Pairing
        </h2>
        <p className="mb-4 text-sm text-gray-500 dark:text-gray-400">
          <span className="font-medium text-gray-700 dark:text-gray-300">
            {request.deviceName || "A Moonlight client"}
          </span>{" "}
          wants to pair. Enter the 4-digit PIN shown on your Moonlight client.
        </p>

        <input
          ref={inputRef}
          type="text"
          inputMode="numeric"
          pattern="[0-9]*"
          maxLength={4}
          placeholder="0000"
          value={pin}
          onChange={e => {
            const v = e.target.value.replace(/\D/g, "").slice(0, 4);
            setPin(v);
          }}
          onKeyDown={e => {
            if (e.key === "Enter") handleSubmit();
            if (e.key === "Escape") handleClose();
          }}
          className="mb-4 block w-full rounded-md border border-gray-300 bg-white px-4 py-2 text-center text-2xl tracking-[0.5em] text-gray-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none dark:border-slate-600 dark:bg-slate-700 dark:text-white"
        />

        <div className="flex justify-end gap-2">
          <Button size="SM" theme="light" text="Cancel" onClick={handleClose} disabled={loading} />
          <Button
            size="SM"
            theme="primary"
            text={loading ? "Pairing…" : "Pair"}
            onClick={handleSubmit}
            disabled={pin.length !== 4 || loading}
          />
        </div>
      </div>
    </Modal>
  );
}
