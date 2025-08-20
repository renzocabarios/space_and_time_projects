import axios, { type AxiosResponse } from "axios";
import "dotenv/config";

const SCHEMA_NAME = "TEST_RENZO";

async function main(): Promise<void> {
  try {
    const authenticate_response: AxiosResponse<any> = await axios.post(
      "https://proxy.api.makeinfinite.dev/auth/login",
      {
        userId: process.env.USER_ID ?? "",
        password: process.env.PASSWORD ?? "",
      }
    );

    console.log(authenticate_response?.data?.accessToken);

    const response: AxiosResponse<any> = await axios.post(
      "https://api.spaceandtime.dev/v1/sql/ddl",
      {
        sqlText: `CREATE SCHEMA ${SCHEMA_NAME}`,
      },
      {
        headers: {
          apikey: process.env.API_KEY ?? "",
          authorization: `Bearer ${authenticate_response?.data?.accessToken}`,
          originApp: "SpaceAndTime-biscuit",
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
