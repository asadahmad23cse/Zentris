import assert from "node:assert/strict";
import { describe, it } from "node:test";
import dlpCatalog from "../security/dlp-rules.json";
import { scanAndRedactSensitiveData } from "../guards/dlpGuard";

describe("versioned DLP catalog", () => {
  it("has stable unique rule identifiers and precompilable expressions", () => {
    assert.equal(dlpCatalog.version, 1);
    const ids = dlpCatalog.rules.map((rule) => rule.id);
    assert.equal(new Set(ids).size, ids.length);
    for (const rule of dlpCatalog.rules) assert.doesNotThrow(() => new RegExp(rule.pattern, rule.flags));
  });

  it("redacts provider credentials without returning their values in findings", () => {
    const openai = `sk-proj-${"A1b2".repeat(8)}`;
    const github = `ghp_${"a".repeat(36)}`;
    const database = "postgresql://admin:super-secret@db.internal:5432/app";
    const result = scanAndRedactSensitiveData(`keys ${openai} ${github} ${database}`);

    assert.match(result.redacted, /\[REDACTED:OPENAI_KEY\]/);
    assert.match(result.redacted, /\[REDACTED:GITHUB_TOKEN\]/);
    assert.match(result.redacted, /\[REDACTED:DATABASE_URL\]/);
    assert.equal(result.redacted.includes(openai), false);
    assert.equal(JSON.stringify(result.findings).includes(openai), false);
  });

  it("uses deterministic validators and prefers specific validated identifiers", () => {
    const result = scanAndRedactSensitiveData(
      "card 4242 4242 4242 4242; aadhaar 2000 0000 0009; iban GB82 WEST 1234 5698 7654 32"
    );
    assert.ok(result.detectedTypes.includes("PAYMENT_CARD"));
    assert.ok(result.detectedTypes.includes("INDIA_AADHAAR"));
    assert.ok(result.detectedTypes.includes("IBAN"));

    const invalid = scanAndRedactSensitiveData("invalid card 4242 4242 4242 4241 and ip 999.999.999.999");
    assert.equal(invalid.detectedTypes.includes("PAYMENT_CARD"), false);
    assert.equal(invalid.findings.some((finding) => finding.ruleId === "ipv4"), false);
  });

  it("redacts contextual personal and Indian financial data with typed markers", () => {
    const result = scanAndRedactSensitiveData(
      "full name: Asha Singh; DOB: 1990-02-14; PAN ABCDE1234F; IFSC HDFC0001234; account no: 123456789012"
    );
    assert.match(result.redacted, /\[REDACTED:PERSON_NAME\]/);
    assert.match(result.redacted, /\[REDACTED:DATE_OF_BIRTH\]/);
    assert.match(result.redacted, /\[REDACTED:INDIA_PAN\]/);
    assert.match(result.redacted, /\[REDACTED:INDIA_IFSC\]/);
    assert.match(result.redacted, /\[REDACTED:INDIA_BANK_ACCOUNT\]/);
  });

  it("redacts base64 and hex encoded provider credentials", () => {
    const key = `sk-proj-${"z".repeat(48)}`;
    const base64 = Buffer.from(key, "utf8").toString("base64");
    const hex = Buffer.from(key, "utf8").toString("hex");
    const result = scanAndRedactSensitiveData(`encoded ${base64} and ${hex}`, "input");
    assert.equal(result.redacted.includes(base64), false);
    assert.equal(result.redacted.includes(hex), false);
    assert.equal(result.findings.filter((finding) => finding.ruleId.startsWith("encoded_")).length, 2);
  });
});
