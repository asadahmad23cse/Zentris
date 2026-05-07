import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderWithProviders, screen } from "../../../../tests/test-utils";
import { CommunityEngagementButtons } from "./CommunityEngagementButtons";

let mockUseDisableShowPromptsImpl = () => false;

vi.mock("@/app/(dashboard)/hooks/useDisableShowPrompts", () => ({
  useDisableShowPrompts: () => mockUseDisableShowPromptsImpl(),
}));

describe("CommunityEngagementButtons", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseDisableShowPromptsImpl = () => false;
  });

  it("should render", () => {
    renderWithProviders(<CommunityEngagementButtons />);
    expect(screen.getByRole("link", { name: /community/i })).toBeInTheDocument();
  });

  it("should render Community button with correct link", () => {
    renderWithProviders(<CommunityEngagementButtons />);

    const communityLink = screen.getByRole("link", { name: /community/i });
    expect(communityLink).toBeInTheDocument();
    expect(communityLink).toHaveAttribute("href", "https://github.com/asadahmad23cse/Zentris/discussions");
    expect(communityLink).toHaveAttribute("target", "_blank");
    expect(communityLink).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("should render Star Zentris button with correct link", () => {
    renderWithProviders(<CommunityEngagementButtons />);

    const starOnGithubLink = screen.getByRole("link", { name: /star zentris/i });
    expect(starOnGithubLink).toBeInTheDocument();
    expect(starOnGithubLink).toHaveAttribute("href", "https://github.com/asadahmad23cse/Zentris");
    expect(starOnGithubLink).toHaveAttribute("target", "_blank");
    expect(starOnGithubLink).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("should not render buttons when prompts are disabled", () => {
    mockUseDisableShowPromptsImpl = () => true;

    renderWithProviders(<CommunityEngagementButtons />);

    expect(screen.queryByRole("link", { name: /community/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /star zentris/i })).not.toBeInTheDocument();
  });
});


