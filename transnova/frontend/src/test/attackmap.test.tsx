// The ATT&CK mapping card: order, labels, honest wording and the empty state.
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { AttackMap, eventTechniques, rowsFromDetections, tacticName } from "../components/AttackMap";
import type { ExplainedDetection } from "../api/types";

afterEach(cleanup);

const dets: ExplainedDetection[] = [
  { rule: "W-AUTH-04", name: "Decoy credential accepted", alerting: true, confidence: "high", owasp_2025: "A07:2025-Authentication Failures",
    attack: [{ technique: "T1078", name: "Valid Accounts", tactics: ["persistence", "initial-access"], url: "https://attack.mitre.org/techniques/T1078", status: "candidate" }] },
  { rule: "W-ENUM-02", name: "Route scan", alerting: true, attack: [{ technique: "T1595.003", name: "Wordlist Scanning", tactics: ["reconnaissance"], status: "candidate" }] },
  { rule: "W-AUTH-01", name: "Failed web login", alerting: false, attack: [] },
];

describe("ATT&CK mapping", () => {
  it("orders rows by kill chain and shows tactic, technique, rule and OWASP", () => {
    render(<AttackMap rows={rowsFromDetections(dets)} />);
    const rows = screen.getAllByRole("listitem");
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByText("Reconnaissance")).toBeTruthy();         // recon sorts before persistence
    expect(within(rows[1]).getByText("T1078").closest("a")?.getAttribute("href")).toBe("https://attack.mitre.org/techniques/T1078");
    expect(within(rows[1]).getByText(/Valid Accounts/)).toBeTruthy();
    expect(within(rows[1]).getByText("W-AUTH-04")).toBeTruthy();
    expect(within(rows[1]).getByText("A07:2025-Authentication Failures")).toBeTruthy();
    expect(within(rows[1]).getByText("inferred by rule (candidate)")).toBeTruthy();
  });

  it("says why nothing is mapped instead of showing an empty box", () => {
    render(<AttackMap rows={rowsFromDetections([dets[2]])} empty="nothing mapped here" />);
    expect(screen.getByText("nothing mapped here")).toBeTruthy();
  });

  it("flags a technique unknown to the dataset", () => {
    render(<AttackMap rows={rowsFromDetections([{ rule: "X", name: "x", alerting: true, attack: [{ technique: "T9999", name: null, tactics: [] }] }])} />);
    expect(screen.getByText(/unknown to ATT&CK v20/)).toBeTruthy();
    expect(screen.getByText("Not in dataset")).toBeTruthy();
  });

  it("collects technique IDs from raw sensor detections for table chips", () => {
    expect(eventTechniques([{ rule: "a", attack: [{ technique: "T1190" }, { technique: "T1190" }] }, { rule: "b" }])).toEqual(["T1190"]);
    expect(tacticName("command-and-control")).toBe("Command and Control");
  });
});
