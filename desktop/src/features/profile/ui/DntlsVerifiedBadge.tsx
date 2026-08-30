import { BadgeCheck } from "lucide-react";

import { safeNpub } from "@/shared/lib/nostrUtils";
import { cn } from "@/shared/lib/cn";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/shared/ui/popover";

export type DntlsVerifiedBadgeProps = {
  approvedAt?: number | null;
  className?: string;
  fqdn: string;
  pubkey: string;
};

export function dntlsProofCopy(input: {
  approvedAt?: number | null;
  fqdn: string;
  pubkey: string;
}) {
  const approvedLabel =
    typeof input.approvedAt === "number" &&
    Number.isFinite(input.approvedAt) &&
    input.approvedAt > 0
      ? new Date(input.approvedAt * 1000)
      : null;
  return {
    identifier: `${input.fqdn}@dntls`,
    provenance:
      "The relay attested that DNTLS trust-root verification bound this name to this key.",
    npub: safeNpub(input.pubkey),
    hexPubkey: input.pubkey,
    approvedLabel:
      approvedLabel && !Number.isNaN(approvedLabel.getTime())
        ? approvedLabel.toLocaleString(undefined, {
            dateStyle: "medium",
            timeStyle: "short",
          })
        : null,
  };
}

export function DntlsVerifiedBadge({
  approvedAt,
  className,
  fqdn,
  pubkey,
}: DntlsVerifiedBadgeProps) {
  const proof = dntlsProofCopy({ approvedAt, fqdn, pubkey });

  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          aria-label={`Show DNTLS verification for ${proof.identifier}`}
          className={cn(
            "inline-flex shrink-0 items-center justify-center rounded-full text-primary hover:text-primary/80 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
            className,
          )}
          data-testid="dntls-verified-badge"
          onClick={(event) => {
            event.stopPropagation();
          }}
        >
          <BadgeCheck aria-hidden="true" className="h-3.5 w-3.5" />
        </button>
      </PopoverTrigger>
      <PopoverContent
        align="start"
        className="w-80"
        data-testid="dntls-proof-panel"
        onClick={(event) => event.stopPropagation()}
        side="top"
        sideOffset={8}
      >
        <div className="flex flex-col gap-3">
          <p className="truncate font-mono text-sm font-semibold leading-5">
            {proof.identifier}
          </p>
          <p className="text-xs leading-5 text-muted-foreground">
            {proof.provenance}
          </p>
          {proof.approvedLabel ? (
            <p className="text-xs leading-5 text-muted-foreground">
              Approved {proof.approvedLabel}
            </p>
          ) : null}
          {proof.npub ? (
            <p className="break-all font-mono text-2xs text-muted-foreground">
              {proof.npub}
            </p>
          ) : null}
          <p className="break-all font-mono text-2xs text-muted-foreground">
            {proof.hexPubkey}
          </p>
        </div>
      </PopoverContent>
    </Popover>
  );
}
