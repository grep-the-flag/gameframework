import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import App from "./App";
import "./i18n";

test("renders the translated app title", () => {
  render(<App />);
  expect(screen.getByRole("heading", { name: "Gameframework" })).toBeInTheDocument();
});
