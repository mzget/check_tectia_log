import fs from "fs";
import es from "event-stream";
import csv from "csv-stringify";
import { uniqBy, isEmpty } from "lodash";

type TectiaHandshake = {
  session_id: string;
  username: string;
  kex_algorithm: string;
  hostkey_algorithm: string;
  cipher: string;
  mac: string;
  compression: string;
};

function main() {
  // Make sure we got a filename on the command line.
  if (process.argv.length < 3) {
    console.log("Usage: node " + process.argv[1] + " FILENAME");
    process.exit(1);
  }
  // Read the file and print its contents.
  const filename = process.argv[2];
  let handshakes = [] as Array<TectiaHandshake>;
  let s = fs
    .createReadStream(filename)
    .pipe(es.split())
    .pipe(
      es
        .mapSync((line: string) => {
          //pause the readstream
          s.pause();
          if (line.includes("LOG EVENT")) {
            let item = {} as TectiaHandshake;
            let session_id = line.split("Session-Id: ")[1];

            // let strs = line.split(" servant]");
            // let session_id = strs[0].split("debug[")[1];

            if (line.includes("Algorithm_negotiation_success")) {
              const matcheds = line.split(",");
              //   console.log("servant_id: ", session_id, matcheds);
              item = {
                ...item,
                kex_algorithm: matcheds[2].split("=")[1],
                hostkey_algorithm: matcheds[3].split("=")[1],
                cipher: matcheds[4].split("=")[1],
                mac: matcheds[5].split("=")[1],
                compression: matcheds[6].split("=")[1],
                session_id: session_id,
              };
            }

            if (line.includes("Login_success")) {
              let username = line.split("Username: ")[1].split(",")[0];
              //   console.log("Username: ", session_id, username);

              handshakes.forEach((v) => {
                if (v.session_id === session_id) {
                  v.username = username;
                }
              });
            }
            if (!isEmpty(item)) handshakes.push(item);
          }
          s.resume();
        })
        .on("error", function (err) {
          console.log("Error:", err);
        })
        .on("end", function () {
          let output = uniqBy(
            handshakes,
            (item: TectiaHandshake) => item.username
          );

          csv.stringify(
            output,
            {
              columns: [
                "username",
                "kex_algorithm",
                "hostkey_algorithm",
                "cipher",
                "mac",
                "compression",
                "session_id",
              ],
              header: true,
            },
            (e, out) => {
              fs.writeFileSync("data.csv", out);
              console.log("Finish: ", output);
            }
          );
        })
    );
}

main();
