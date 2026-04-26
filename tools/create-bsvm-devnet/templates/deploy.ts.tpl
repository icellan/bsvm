import { ethers, network } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(`Deploying Hello from ${deployer.address} on ${network.name}`);

  const factory = await ethers.getContractFactory("Hello");
  const contract = await factory.deploy("hello, {{PROJECT_NAME}}");
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log(`Hello deployed to ${address}`);

  const greeting = await contract.greeting();
  console.log(`Initial greeting: "${greeting}"`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
