import { expect, test } from "@playwright/test";

test.use({ viewport: { width: 390, height: 844 } });

test("long error messages and wide tables stay contained on mobile", async ({ page }) => {
  await page.goto("/login?redirect=/");
  await expect(page.locator(".login-card")).toBeVisible();

  await page.evaluate(() => {
    const error = document.createElement("p");
    error.className = "login-error";
    error.textContent = `Connection failed: ${"PROVIDER_FAILURE_TOKEN_".repeat(50)}`;
    document.querySelector(".login-form")?.prepend(error);

    const tableWrap = document.createElement("div");
    tableWrap.className = "table-wrap";
    tableWrap.innerHTML = `
      <table><tbody><tr>
        <td>${"very-long-provider-response-token-".repeat(20)}</td>
      </tr></tbody></table>
    `;
    document.querySelector("#app")?.append(tableWrap);
  });

  const measurements = await page.evaluate(() => {
    const root = document.documentElement;
    const tableWrap = document.querySelector(".table-wrap");
    return {
      pageOverflows: root.scrollWidth > root.clientWidth,
      tableHasLocalScroll: tableWrap.scrollWidth > tableWrap.clientWidth,
    };
  });

  expect(measurements.pageOverflows).toBe(false);
  expect(measurements.tableHasLocalScroll).toBe(true);
});
