import axios, { type AxiosResponse } from "axios";
import "dotenv/config";

async function main(): Promise<void> {
  try {
    const response: AxiosResponse<any> = await axios.post(
      "https://proxy.api.makeinfinite.dev/v1/sql",
      {
        sqlText: "CREATE SCHEMA RENZO_TEST",
      },
      {
        headers: {
          apikey: process.env.API_KEY ?? "",
        },
      }
    );
    console.log("Data:", response.data);
  } catch (error: unknown) {
    if (axios.isAxiosError(error)) {
      console.error("Axios error:", error.message);
    } else {
      console.error("Unexpected error:", error);
    }
  }
}

// Run functions
main()
  .then(() => {
    console.log("Success");
  })
  .catch((e) => {
    console.log(e);
    console.log("Error");
  });
