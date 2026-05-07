import React, { useState } from "react";
import { Input } from "antd";
import { SearchOutlined, ArrowRightOutlined } from "@ant-design/icons";
import { GuardrailCardInfo, ALL_CARDS } from "./guardrail_garden_data";
import GuardrailCard from "./guardrail_garden_card";
import GuardrailDetailView from "./guardrail_garden_detail";

interface GuardrailGardenProps {
  accessToken: string | null;
  onGuardrailCreated: () => void;
}

const GuardrailGarden: React.FC<GuardrailGardenProps> = ({ accessToken, onGuardrailCreated }) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCard, setSelectedCard] = useState<GuardrailCardInfo | null>(null);
  const [showAllZentris, setShowAllZentris] = useState(false);
  const CARDS_PER_ROW = 5;
  const VISIBLE_ROWS = 2;

  const filteredCards = ALL_CARDS.filter((card) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      card.name.toLowerCase().includes(q) ||
      card.description.toLowerCase().includes(q) ||
      card.tags.some((t) => t.toLowerCase().includes(q))
    );
  });

  const ZentrisCards = filteredCards.filter((c) => c.category === "Zentris");
  const partnerCards = filteredCards.filter((c) => c.category === "partner");

  if (selectedCard) {
    return (
      <GuardrailDetailView
        card={selectedCard}
        onBack={() => setSelectedCard(null)}
        accessToken={accessToken}
        onGuardrailCreated={onGuardrailCreated}
      />
    );
  }

  return (
    <div>
      {/* Search Bar */}
      <div style={{ marginBottom: 24 }}>
        <Input
          size="large"
          placeholder="Search guardrails"
          prefix={<SearchOutlined style={{ color: "#9ca3af" }} />}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{ borderRadius: 8 }}
        />
      </div>

      {/* Zentris Content Filter Section */}
      <div style={{ marginBottom: 40 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
          <h2 style={{ fontSize: 20, fontWeight: 600, color: "#111827", margin: 0 }}>Zentris Content Filter</h2>
          <span
            style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 14, color: "#1a73e8", cursor: "pointer" }}
            onClick={() => setShowAllZentris(!showAllZentris)}
          >
            {showAllZentris ? (
              <>Show less</>
            ) : (
              <>
                <ArrowRightOutlined style={{ fontSize: 12 }} />
                {`Show all (${ZentrisCards.length})`}
              </>
            )}
          </span>
        </div>
        <p style={{ fontSize: 13, color: "#6b7280", margin: "4px 0 20px 0" }}>
          Built-in guardrails powered by Zentris. Zero latency, no external dependencies, no additional cost.
        </p>
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
          gap: 16,
        }}>
          {(showAllZentris ? ZentrisCards : ZentrisCards.slice(0, CARDS_PER_ROW * VISIBLE_ROWS)).map((card) => (
            <GuardrailCard key={card.id} card={card} onClick={() => setSelectedCard(card)} />
          ))}
        </div>
      </div>

      {/* Partner Guardrails Section */}
      <div style={{ marginBottom: 40 }}>
        <h2 style={{ fontSize: 20, fontWeight: 600, color: "#111827", margin: "0 0 4px 0" }}>Partner Guardrails</h2>
        <p style={{ fontSize: 13, color: "#6b7280", margin: "4px 0 20px 0" }}>
          Third-party guardrail integrations from leading AI security providers.
        </p>
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
          gap: 16,
        }}>
          {partnerCards.map((card) => (
            <GuardrailCard key={card.id} card={card} onClick={() => setSelectedCard(card)} />
          ))}
        </div>
      </div>
    </div>
  );
};

export default GuardrailGarden;


