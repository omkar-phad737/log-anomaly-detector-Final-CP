import { useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { SAMPLE_LOGS, type SampleLog } from "@/lib/samples";
import { cn } from "@/lib/utils";
import { FileUp, Play, ClipboardPaste, FlaskConical } from "lucide-react";

const MAX_SIZE = 512 * 1024; // 512 KB
const ALLOWED_EXT = /\.(txt|log|out)$/i;

/** Strip anything that could be path-traversal or odd on Windows. */
export function sanitizeFilename(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? "log";
  const clean = base.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 80);
  return clean || "log.txt";
}

export function InputPanel({
  logText,
  filename,
  onTextChange,
  onFilenameChange,
  onAnalyze,
  onLoadSample,
}: {
  logText: string;
  filename: string;
  onTextChange: (text: string) => void;
  onFilenameChange: (name: string) => void;
  onAnalyze: () => void;
  onLoadSample: (sample: SampleLog) => void;
}) {
  const fileInput = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);

  const readFile = (file: File) => {
    if (!ALLOWED_EXT.test(file.name)) {
      toast.error("Only .txt, .log or .out files are accepted.");
      return;
    }
    if (file.size > MAX_SIZE) {
      toast.error("File too large — the limit is 512 KB.");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      onTextChange(String(reader.result ?? ""));
      onFilenameChange(sanitizeFilename(file.name));
      toast.success(`Loaded ${sanitizeFilename(file.name)}`);
    };
    reader.onerror = () => toast.error("Could not read that file.");
    reader.readAsText(file);
  };

  return (
    <div className="flex flex-col gap-4">
      <Tabs defaultValue="upload">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="upload" className="gap-1.5 text-xs">
            <FileUp className="size-3.5" /> Upload
          </TabsTrigger>
          <TabsTrigger value="paste" className="gap-1.5 text-xs">
            <ClipboardPaste className="size-3.5" /> Paste
          </TabsTrigger>
          <TabsTrigger value="samples" className="gap-1.5 text-xs">
            <FlaskConical className="size-3.5" /> Samples
          </TabsTrigger>
        </TabsList>

        <TabsContent value="upload" className="mt-3">
          <div
            role="button"
            tabIndex={0}
            onClick={() => fileInput.current?.click()}
            onKeyDown={(e) => e.key === "Enter" && fileInput.current?.click()}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              const file = e.dataTransfer.files?.[0];
              if (file) readFile(file);
            }}
            className={cn(
              "flex cursor-pointer flex-col items-center justify-center gap-1.5 rounded-lg border border-dashed px-4 py-8 text-center transition-colors",
              dragOver
                ? "border-cyan-400/70 bg-cyan-400/5"
                : "border-border/70 hover:border-cyan-400/40 hover:bg-cyan-400/[0.03]",
            )}
          >
            <FileUp className="size-6 text-muted-foreground" />
            <p className="text-sm font-medium">
              Drop a log file here, or click to browse
            </p>
            <p className="text-xs text-muted-foreground">
              .txt / .log / .out · max 512 KB · content is parsed, never executed
            </p>
            <input
              ref={fileInput}
              type="file"
              accept=".txt,.log,.out"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) readFile(file);
                e.target.value = "";
              }}
            />
          </div>
        </TabsContent>

        <TabsContent value="paste" className="mt-3">
          <Textarea
            value={logText}
            onChange={(e) => onTextChange(e.target.value)}
            placeholder={
              "Paste log lines, e.g.\n\n2026-09-30 10:00:01 user=101 event=LOGIN\n2026-09-30 10:00:02 user=101 event=AUTH_SUCCESS"
            }
            className="h-44 resize-y bg-background/50 font-mono text-xs"
          />
        </TabsContent>

        <TabsContent value="samples" className="mt-3">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {SAMPLE_LOGS.map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() => onLoadSample(s)}
                className="rounded-lg border border-border/60 bg-background/40 px-3 py-2.5 text-left transition-colors hover:border-cyan-400/40 hover:bg-cyan-400/[0.04]"
              >
                <div className="text-sm font-medium">{s.name.replace(/^Load /, "")}</div>
                <div className="text-xs text-muted-foreground">{s.description}</div>
              </button>
            ))}
          </div>
        </TabsContent>
      </Tabs>

      <div className="flex flex-wrap items-center gap-3">
        <Button
          size="lg"
          onClick={onAnalyze}
          disabled={!logText.trim()}
          className="gap-2 bg-cyan-500 text-cyan-950 hover:bg-cyan-400"
        >
          <Play className="size-4" />
          Analyze Log
        </Button>
        {filename && (
          <span className="rounded-md border border-border/60 bg-background/40 px-2 py-1 font-mono text-xs text-muted-foreground">
            {filename}
          </span>
        )}
      </div>
    </div>
  );
}
