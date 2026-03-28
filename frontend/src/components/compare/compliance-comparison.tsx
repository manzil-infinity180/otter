import clsx from "clsx";
import type { MultiCompareImageSnapshot } from "../../lib/api";

interface ComplianceComparisonProps {
  images: MultiCompareImageSnapshot[];
}

function Check({ ok }: { ok: boolean }) {
  return (
    <span className={clsx("inline-block text-lg", ok ? "text-emerald-500" : "text-ink-300 dark:text-ink-600")}>
      {ok ? "\u2713" : "\u2717"}
    </span>
  );
}

export function ComplianceComparison({ images }: ComplianceComparisonProps) {
  const hasCompliance = images.some((img) => img.compliance);
  if (!hasCompliance) return null;

  return (
    <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
      <h3 className="font-display text-lg text-ink-900 dark:text-white">Supply Chain Comparison</h3>
      <div className="mt-4 overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="text-ink-500 dark:text-ink-400">
            <tr>
              <th className="pb-3 pr-6">Check</th>
              {images.map((img, i) => (
                <th key={i} className="pb-3 pr-6">
                  <span className="flex items-center gap-1.5">
                    <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: img.color }} />
                    {img.image_name.length > 25 ? img.image_name.slice(0, 25) + "..." : img.image_name}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-200 dark:divide-ink-800">
            <tr>
              <td className="py-3 pr-6 text-ink-900 dark:text-white">SBOM available</td>
              {images.map((img, i) => (
                <td key={i} className="py-3 pr-6"><Check ok={img.compliance?.has_sbom ?? false} /></td>
              ))}
            </tr>
            <tr>
              <td className="py-3 pr-6 text-ink-900 dark:text-white">Signatures</td>
              {images.map((img, i) => (
                <td key={i} className="py-3 pr-6"><Check ok={img.compliance?.has_signature ?? false} /></td>
              ))}
            </tr>
            <tr>
              <td className="py-3 pr-6 text-ink-900 dark:text-white">Attestations</td>
              {images.map((img, i) => (
                <td key={i} className="py-3 pr-6"><Check ok={img.compliance?.has_attestation ?? false} /></td>
              ))}
            </tr>
            <tr>
              <td className="py-3 pr-6 text-ink-900 dark:text-white">SLSA Level</td>
              {images.map((img, i) => (
                <td key={i} className="py-3 pr-6 text-ink-600 dark:text-ink-300">
                  {img.compliance?.slsa_level || "N/A"}
                </td>
              ))}
            </tr>
            <tr>
              <td className="py-3 pr-6 text-ink-900 dark:text-white">Scorecard</td>
              {images.map((img, i) => (
                <td key={i} className="py-3 pr-6 text-ink-600 dark:text-ink-300">
                  {img.compliance?.scorecard_score ? `${img.compliance.scorecard_score.toFixed(1)}/10` : "N/A"}
                </td>
              ))}
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
