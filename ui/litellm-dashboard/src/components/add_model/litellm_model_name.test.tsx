import { render } from "@testing-library/react";
import { Form } from "antd";
import { describe, expect, it } from "vitest";
import { getPlaceholder, Providers } from "../provider_info_helpers";
import ZentrisModelNameField from "./Zentris_model_name";

describe("ZentrisModelNameField", () => {
  it("should render", () => {
    const { getByText } = render(
      <Form>
        <ZentrisModelNameField
          selectedProvider={Providers.OpenAI}
          providerModels={[]}
          getPlaceholder={getPlaceholder}
        />
      </Form>,
    );
    expect(getByText("Zentris Model Name(s)")).toBeInTheDocument();
  });

  it("should show Azure placeholder as 'my-deployment'", () => {
    const { getByPlaceholderText, queryByPlaceholderText } = render(
      <Form>
        <ZentrisModelNameField selectedProvider={Providers.Azure} providerModels={[]} getPlaceholder={getPlaceholder} />
      </Form>,
    );
    expect(getByPlaceholderText("my-deployment")).toBeInTheDocument();
    expect(queryByPlaceholderText("gpt-3.5-turbo")).toBeNull();
  });
});



