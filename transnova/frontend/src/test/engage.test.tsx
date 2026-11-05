import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { EngageList } from "../components/Engage";

afterEach(cleanup);

describe("MITRE Engage list", () => {
  it("shows activity, goal and approach once per rule and activity", () => {
    const e = { activity: "Decoy Credential", goal: "Expose", approach: "Detect", description: "Planted credentials." };
    render(<EngageList items={[{ rule: "W-AUTH-04", engage: [e, e] }]} rules />);
    expect(screen.getAllByText("Decoy Credential")).toHaveLength(1);
    expect(screen.getByText("Expose · Detect")).toBeTruthy();
    expect(screen.getByText("W-AUTH-04")).toBeTruthy();
  });
  it("is honest when nothing is recorded", () => {
    render(<EngageList items={[{ rule: "X", engage: [] }]} />);
    expect(screen.getByText(/No deception activity/)).toBeTruthy();
  });
});
