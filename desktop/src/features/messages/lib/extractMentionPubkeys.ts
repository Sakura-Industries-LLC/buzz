import { getMentionOffsets } from "./hasMention";
import type { DntlsVerifiedName } from "@/shared/api/dntls";

export type MentionPubkeyCandidate = {
  displayName: string | null;
  isMember: boolean;
  pubkey?: string;
};

type MentionMatch = {
  displayName: string;
  pubkey?: string;
};

function normalizeDisplayName(name: string): string {
  return name.trim().toLowerCase();
}

/**
 * Returns explicit selected mention pubkeys and manually typed channel-member
 * mentions. At each `@` offset, only the longest valid display name wins so a
 * member whose name prefixes another member is not spuriously tagged.
 */
export function extractMentionPubkeys({
  text,
  selectedMentions,
  selectedDisplayNames,
  memberCandidates,
  verifiedNames,
}: {
  text: string;
  selectedMentions: ReadonlyMap<string, string>;
  selectedDisplayNames?: Iterable<string>;
  memberCandidates: readonly MentionPubkeyCandidate[];
  verifiedNames?: ReadonlyMap<string, DntlsVerifiedName>;
}): string[] {
  const verifiedLabels = new Set(
    [...(verifiedNames?.values() ?? [])].map((name) => name.fqdn.toLowerCase()),
  );
  const selectedNames = new Set(
    [...selectedMentions.keys(), ...(selectedDisplayNames ?? [])].map(
      normalizeDisplayName,
    ),
  );
  const matchesByOffset = new Map<number, MentionMatch[]>();

  const addMatches = (displayName: string, pubkey?: string) => {
    const trimmedName = displayName.trim();
    if (!trimmedName) return;
    const verified = verifiedLabels.has(trimmedName.toLowerCase());

    for (const offset of getMentionOffsets(text, trimmedName)) {
      if (
        verified &&
        /^(?:[a-z0-9-]|\.[a-z0-9-])/i.test(
          text.slice(offset + trimmedName.length + 1),
        )
      )
        continue;
      const matches = matchesByOffset.get(offset) ?? [];
      matches.push({ displayName: trimmedName, pubkey });
      matchesByOffset.set(offset, matches);
    }
  };

  for (const [displayName, pubkey] of selectedMentions) {
    addMatches(displayName, pubkey);
  }
  for (const displayName of selectedDisplayNames ?? []) {
    addMatches(displayName);
  }
  for (const candidate of memberCandidates) {
    if (
      candidate.pubkey &&
      candidate.isMember &&
      candidate.displayName &&
      !selectedNames.has(normalizeDisplayName(candidate.displayName))
    ) {
      addMatches(candidate.displayName, candidate.pubkey);
    }
  }
  for (const [pubkey, name] of verifiedNames ?? []) {
    // Dots delimit DNS labels, not mention punctuation inside a longer name.
    for (const offset of getMentionOffsets(text, name.fqdn)) {
      const rest = text.slice(offset + name.fqdn.length + 1);
      if (/^(?:[a-z0-9-]|\.[a-z0-9-])/i.test(rest)) continue;
      // Verified names override selected/self-asserted display-name aliases.
      matchesByOffset.set(offset, [{ displayName: name.fqdn, pubkey }]);
    }
  }

  const winningPubkeys = new Set<string>();
  for (const matches of matchesByOffset.values()) {
    const longestNameLength = Math.max(
      ...matches.map((match) => match.displayName.length),
    );
    for (const match of matches) {
      if (match.pubkey && match.displayName.length === longestNameLength) {
        winningPubkeys.add(match.pubkey);
      }
    }
  }

  const pubkeys: string[] = [];
  for (const [, pubkey] of selectedMentions) {
    if (winningPubkeys.delete(pubkey)) pubkeys.push(pubkey);
  }
  for (const candidate of memberCandidates) {
    if (candidate.pubkey && winningPubkeys.delete(candidate.pubkey)) {
      pubkeys.push(candidate.pubkey);
    }
  }
  for (const [pubkey] of verifiedNames ?? []) {
    if (winningPubkeys.delete(pubkey)) pubkeys.push(pubkey);
  }
  return pubkeys;
}
