import { describe, expect, it, vi } from "vitest";
import { prepareModelAddRequest } from "./handle_add_model_submit";

vi.mock("../molecules/notifications_manager", () => ({
  default: {
    fromBackend: vi.fn(),
  },
}));

describe("prepareModelAddRequest", () => {
  it("returns deployment data for the most basic form", async () => {
    const formValues = {
      model_mappings: [
        {
          public_name: "Public Model",
          Zentris_model: "Zentris/public",
        },
      ],
      model_name: "custom-model-name",
      base_model: "gpt-4",
      team_id: "team-123",
      model_access_group: ["group-1"],
      input_cost_per_token: "2000000",
      output_cost_per_token: "1000000",
    };

    const deployments = await prepareModelAddRequest({ ...formValues }, "token", null);

    expect(deployments).toHaveLength(1);
    const [deployment] = deployments!;
    expect(deployment.modelName).toBe("Public Model");
    expect(deployment.ZentrisParamsObj.model).toBe("custom-model-name");
    expect(deployment.ZentrisParamsObj.input_cost_per_token).toBe(2);
    expect(deployment.ZentrisParamsObj.output_cost_per_token).toBe(1);
    expect(deployment.modelInfoObj.base_model).toBe("gpt-4");
    expect(deployment.modelInfoObj.access_groups).toEqual(["group-1"]);
    expect(deployment.modelInfoObj.team_id).toBe("team-123");
  });

  it("uses a lowercase fallback for unrecognized custom providers", async () => {
    const fallbackValues = {
      model_mappings: [
        {
          public_name: "Petals Model",
          Zentris_model: "petals/model",
        },
      ],
      model_name: "petals/model",
      custom_llm_provider: "Petals",
    };

    const deployments = await prepareModelAddRequest({ ...fallbackValues }, "token", null);

    expect(deployments).toHaveLength(1);
    const [deployment] = deployments!;
    expect(deployment.ZentrisParamsObj.custom_llm_provider).toBe("petals");
  });

  it("ignores Zentris_credential_name inside Zentris Params JSON", async () => {
    const formValues = {
      model_mappings: [
        {
          public_name: "Public Model",
          Zentris_model: "Zentris/public",
        },
      ],
      model_name: "custom-model-name",
      Zentris_credential_name: "selected-credential",
      Zentris_extra_params: JSON.stringify({
        Zentris_credential_name: "from-json",
        timeout: 5,
      }),
    };

    const deployments = await prepareModelAddRequest({ ...formValues }, "token", null);

    expect(deployments).toHaveLength(1);
    const [deployment] = deployments!;
    expect(deployment.ZentrisParamsObj.Zentris_credential_name).toBe("selected-credential");
    expect(deployment.ZentrisParamsObj.timeout).toBe(5);
  });
});


