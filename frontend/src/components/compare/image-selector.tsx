import { useState } from "react";
import type { MultiCompareImage, PresetComparison } from "../../lib/api";

interface ImageSelectorProps {
  images: MultiCompareImage[];
  presets: PresetComparison[];
  onImagesChange: (images: MultiCompareImage[]) => void;
  onCompare: () => void;
  isComparing: boolean;
}

export function ImageSelector({ images, presets, onImagesChange, onCompare, isComparing }: ImageSelectorProps) {
  const [draft, setDraft] = useState("");

  const addImage = (name: string) => {
    const trimmed = name.trim();
    if (!trimmed || images.length >= 3) return;
    if (images.some((img) => img.name === trimmed)) return;
    onImagesChange([...images, { name: trimmed }]);
    setDraft("");
  };

  const removeImage = (index: number) => {
    onImagesChange(images.filter((_, i) => i !== index));
  };

  const loadPreset = (preset: PresetComparison) => {
    onImagesChange(preset.images.slice(0, 3));
  };

  return (
    <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
      <h2 className="font-display text-xl text-ink-900 dark:text-white">Compare Container Images</h2>
      <p className="mt-1 text-sm text-ink-500 dark:text-ink-400">
        Select 2-3 images to compare vulnerability posture, packages, and supply chain security.
      </p>

      {/* Image inputs */}
      <div className="mt-5 space-y-3">
        {images.map((img, i) => (
          <div key={i} className="flex items-center gap-2">
            <div className="h-3 w-3 flex-shrink-0 rounded-full" style={{ backgroundColor: ["#0ea5e9", "#f59e0b", "#10b981"][i] }} />
            <input
              type="text"
              value={img.name}
              onChange={(e) => {
                const next = [...images];
                next[i] = { ...next[i], name: e.target.value };
                onImagesChange(next);
              }}
              placeholder={`Image ${i + 1} (e.g., nginx:latest)`}
              className="flex-1 rounded-md border border-ink-200 bg-white px-3 py-2 text-sm text-ink-900 placeholder:text-ink-400 dark:border-ink-700 dark:bg-ink-800 dark:text-white dark:placeholder:text-ink-500"
            />
            <button
              type="button"
              onClick={() => removeImage(i)}
              className="rounded px-2 py-1 text-xs text-ink-400 hover:bg-ink-100 hover:text-ink-700 dark:hover:bg-ink-800 dark:hover:text-ink-200"
            >
              Remove
            </button>
          </div>
        ))}

        {images.length < 3 ? (
          <form
            className="flex items-center gap-2"
            onSubmit={(e) => { e.preventDefault(); addImage(draft); }}
          >
            <div className="h-3 w-3 flex-shrink-0 rounded-full border-2 border-dashed border-ink-300 dark:border-ink-600" />
            <input
              type="text"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder={images.length === 0 ? "Add first image (e.g., nginx:latest)" : "Add another image..."}
              className="flex-1 rounded-md border border-ink-200 bg-white px-3 py-2 text-sm text-ink-900 placeholder:text-ink-400 dark:border-ink-700 dark:bg-ink-800 dark:text-white dark:placeholder:text-ink-500"
            />
            <button
              type="submit"
              disabled={!draft.trim()}
              className="rounded-md bg-tide px-3 py-2 text-sm font-medium text-white transition hover:bg-sky-600 disabled:opacity-50"
            >
              Add
            </button>
          </form>
        ) : null}
      </div>

      {/* Presets */}
      <div className="mt-5">
        <p className="text-xs font-medium uppercase tracking-wider text-ink-500 dark:text-ink-400">Quick presets</p>
        <div className="mt-2 flex flex-wrap gap-2">
          {presets.map((preset) => (
            <button
              key={preset.id}
              type="button"
              onClick={() => loadPreset(preset)}
              className="rounded-md border border-ink-200 px-3 py-1.5 text-xs font-medium text-ink-700 transition hover:border-tide hover:text-tide dark:border-ink-700 dark:text-ink-300 dark:hover:border-sky-400 dark:hover:text-sky-400"
              title={preset.description}
            >
              {preset.name}
            </button>
          ))}
        </div>
      </div>

      {/* Compare button */}
      <div className="mt-5">
        <button
          type="button"
          onClick={onCompare}
          disabled={images.length < 2 || images.some((img) => !img.name.trim()) || isComparing}
          className="rounded-md bg-ink-900 px-6 py-2.5 text-sm font-medium text-white transition hover:bg-ink-800 disabled:opacity-50 dark:bg-white dark:text-ink-900 dark:hover:bg-ink-100"
        >
          {isComparing ? "Comparing..." : `Compare ${images.length} images`}
        </button>
      </div>
    </div>
  );
}
