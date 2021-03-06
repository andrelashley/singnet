const fs = require('fs')

const Escrow = artifacts.require('Escrow.sol')
const Agent = artifacts.require('agent/Agent.sol')
const MarketJob = artifacts.require('market/MarketJob.sol')
const MarketJobFactory = artifacts.require('market/MarketJobFactory.sol')
const AgentFactory = artifacts.require('agent/AgentFactory.sol')
const AgentRegistry = artifacts.require('registries/AgentRegistry.sol')
const SingularityNetToken = artifacts.require('tokens/SingularityNetToken.sol')

module.exports = function(deployer, network, accounts) {
  deployer.deploy([
    Agent,
    Escrow,
    MarketJob,
    AgentFactory,
    AgentRegistry,
    MarketJobFactory,
    SingularityNetToken
  ]).then(() => {
    const fileName = "addresses.json"
    const content = {
      Agent: Agent.address,
      Escrow: Escrow.address,
      MarketJob: MarketJob.address,
      AgentFactory: AgentFactory.address,
      AgentRegistry: AgentRegistry.address,
      MarketJobFactory: MarketJobFactory.address,
      SingularityNetToken: SingularityNetToken.address
    }

    fs.writeFile(fileName, JSON.stringify(content), 'utf-8', (err) => {
      if (err) { throw err }
      console.log("Contracts addresses saved in ./" + fileName)
    })
  })
};
