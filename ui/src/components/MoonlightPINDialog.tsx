import { useCallback, useEffect, useRef, useState } from "react";
import { LuCast } from "react-icons/lu";

import { Button } from "@components/Button";
import Modal from "@components/Modal";
import { FieldError } from "@components/InputField";
import { JsonRpcRequest, JsonRpcResponse, useJsonRpc } from "@hooks/useJsonRpc";

interface PairingRequest {
  deviceName: string;
  uniqueID: string;
}

/**
 * MoonlightPINDialog appears automatically when the backend emits a
 * `moonlightPairingRequest` event. The user types the 4-digit PIN shown on
 * their Moonlight client and submits it so the server can complete pairing.
 */
export default function MoonlightPINDialog() {
  const [request, setRequest] = useState<PairingRequest | null>(null);
  const [pin, setPin] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const onRpcRequest = useCallback((req: JsonRpcRequest) => {
    if (req.method === "moonlightPairingRequest") {
      const { deviceName, uniqueID } = req.params as unknown as PairingRequest;
      setRequest({ deviceName, uniqueID });
      setPin("");
      setError(null);
      setLoading(false);
    }
  }, []);

  const { send } = useJsonRpc(onRpcRequest);

  useEffect(() => {
    if (request) {
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [request]);

  const handleClose = useCallback(() => {
    setRequest(null);
    setPin("");
    setError(null);
    setLoading(false);
  }, []);

  const handleSubmit = useCallback(() => {
    if (!request || pin.length !== 4) return;
    setError(null);
    setLoading(true);
    send("submitMoonlightPIN", { uniqueID: request.uniqueID, pin }, (resp: JsonRpcResponse) => {
      setLoading(false);
      if ("error" in resp) {
        setError(resp.error.data || resp.error.message || "Pairing failed");
      } else {
        handleClose();
      }
    });
  }, [request, pin, send, handleClose]);

  if (!request) return null;

  return (
    <div
      onKeyDown={e => {
        if (e.key === "Escape") {
          e.stopPropagation();
          handleClose();
        }
      }}
    >
      <Modal open={true} onClose={handleClose}>
        <div className="mx-auto max-w-md px-4 transition-all duration-300 ease-in-out">
          <div className="pointer-events-auto relative w-full overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm transition-all dark:border-slate-800 dark:bg-slate-900">
            <div className="p-6">
              <div className="flex items-start gap-3.5">
                <LuCast
                  aria-hidden="true"
                  className="mt-[2px] size-[18px] shrink-0 text-blue-600 dark:text-blue-400"
                />
                <div className="min-w-0 flex-1 space-y-2">
                  <h2 className="font-semibold text-slate-950 dark:text-white">
                    Moonlight Pairing Request
                  </h2>
                  <p className="text-sm text-slate-700 dark:text-slate-300">
                    <span className="font-medium text-slate-900 dark:text-slate-100">
                      {request.deviceName || "A Moonlight client"}
                    </span>{" "}
                    wants to pair. Enter the 4-digit PIN shown on your Moonlight client.
                  </p>
                </div>
              </div>

              <div className="mt-5">
                <input
                  ref={inputRef}
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={4}
                  placeholder="0000"
                  value={pin}
                  onChange={e => {
                    setError(null);
                    setPin(e.target.value.replace(/\D/g, "").slice(0, 4));
                  }}
                  onKeyDown={e => {
                    if (e.key === "Enter") handleSubmit();
                  }}
                  className="block w-full rounded-md border border-slate-300 bg-white px-4 py-2.5 text-center text-2xl tracking-[0.6em] text-slate-900 placeholder:tracking-normal placeholder:text-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none dark:border-slate-600 dark:bg-slate-800 dark:text-white dark:placeholder:text-slate-500"
                />
                {error && <FieldError error={error} />}
              </div>

              <div className="mt-6 flex justify-end gap-2">
                <Button
                  size="SM"
                  theme="blank"
                  text="Cancel"
                  onClick={handleClose}
                  disabled={loading}
                />
                <Button
                  size="SM"
                  theme="primary"
                  text={loading ? "Pairing…" : "Pair"}
                  onClick={handleSubmit}
                  disabled={pin.length !== 4 || loading}
                />
              </div>
            </div>
          </div>
        </div>
      </Modal>
    </div>
  );
}
