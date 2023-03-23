const Players = require("../model/player");
const Nations = require("../model/nation");

let clubData = [
  { id: "1", name: "Arsenal" },
  { id: "2", name: "Manchester United" },
  { id: "3", name: "Chelsea" },
  { id: "4", name: "Manchester City" },
  { id: "5", name: "PSG" },
  { id: "6", name: "Inter Milan" },
  { id: "7", name: "Real Madrid" },
  { id: "8", name: "Barcelona" },
];
let postitionData = [
  { id: "1", name: "Goalkeeper" },
  { id: "2", name: "Centre Back" },
  { id: "3", name: "Left Back" },
  { id: "4", name: "Right Back" },
  { id: "5", name: "Sweeper" },
  { id: "6", name: "Center Midfielder" },
  { id: "7", name: "Left Midfielder" },
  { id: "8", name: "Right Midfielder" },
  { id: "9", name: " Attacker " },
];

const PAGE_SIZE = 3;
const PAGE_SIZE_PLAYER_INDEX = 10;
class PlayerController {
  pagingHome(req, res, next) {
    var page = req.query.page;
    if (page) {
      page = parseInt(page);
      if (page < 1) {
        page = 1;
      }
      var skip = (page - 1) * PAGE_SIZE;
    }
    Nations.find({})
      .then((nations) => {
        Players.find({ isCaptain: true })
          .skip(skip)
          .limit(PAGE_SIZE)
          .populate("nation", ["name", "description"])
          .then((players) => {
            Players.countDocuments({ isCaptain: true }).then((total) => {
              console.log(total);
              var totalPage = Math.ceil(total / PAGE_SIZE);
              res.json({
                total: total,
                title: "The list of Players",
                totalPage: totalPage,
                players: players,
                positionList: postitionData,
                clubList: clubData,
                nationsList: nations,
                isLogin: req.session.passport === undefined ? false : true,
              });
            });
            // res.json(players);
          })
          .catch((err) => {
            console.log(err);
            next();
          });
      })
      .catch((err) => {
        console.log(err);
        next();
      });
  }
  home(req, res, next) {
    console.log(req.session);
    var page = req.query.page;
    if (page) {
      page = parseInt(page);
      if (page < 1) {
        page = 1;
      }
      var skip = (page - 1) * PAGE_SIZE;
    }
    Nations.find({})
      .then((nations) => {
        Players.find({ isCaptain: true })
          .skip(skip)
          .limit(PAGE_SIZE)
          .populate("nation", ["name", "description"])
          .then((players) => {
            Players.countDocuments({ isCaptain: true }).then((total) => {
              console.log(total);
              var totalPage = Math.ceil(total / PAGE_SIZE);
              res.render("index", {
                title: "The list of Players",
                totalPage: totalPage,
                players: players,
                positionList: postitionData,
                clubList: clubData,
                nationsList: nations,
                isLogin: req.session.passport === undefined ? false : true,
              });
              // res.json({
              //   totalPage: totalPage,
              //   players: players,
              // });
            });
            // res.json(players);
          })
          .catch((err) => {
            console.log(err);
            next();
          });
      })
      .catch((err) => {
        console.log(err);
        next();
      });
  }
  paging(req, res, next) {
    var page = req.query.page;
    if (page) {
      page = parseInt(page);
      if (page < 1) {
        page = 1;
      }
      var skip = (page - 1) * PAGE_SIZE_PLAYER_INDEX;
    }
    Nations.find({})
      .then((nations) => {
        Players.find()
          .skip(skip)
          .limit(PAGE_SIZE_PLAYER_INDEX)
          .populate("nation", ["name", "description"])
          .then((players) => {
            Players.countDocuments().then((total) => {
              console.log(total);
              var totalPage = Math.ceil(total / PAGE_SIZE_PLAYER_INDEX);
              res.json({
                total: total,
                title: "The list of Players",
                totalPage: totalPage,
                players: players,
                positionList: postitionData,
                clubList: clubData,
                nationsList: nations,
                isLogin: req.session.passport === undefined ? false : true,
              });
            });
            // res.json(players);
          })
          .catch((err) => {
            console.log(err);
            next();
          });
      })
      .catch((err) => {
        console.log(err);
        next();
      });
  }

  index(req, res, next) {
    var page = req.query.page;
    if (page) {
      page = parseInt(page);
      if (page < 1) {
        page = 1;
      }
      var skip = (page - 1) * PAGE_SIZE_PLAYER_INDEX;
    }
    Nations.find({})
      .then((nations) => {
        Players.find()
          .skip(skip)
          .limit(PAGE_SIZE_PLAYER_INDEX)
          .populate("nation", ["name", "description"])
          .then((players) => {
            Players.countDocuments({}).then((total) => {
              console.log(total);
              var totalPage = Math.ceil(total / PAGE_SIZE_PLAYER_INDEX);
              res.render("playerSite", {
                title: "The list of Players",
                totalPage: totalPage,
                players: players,
                positionList: postitionData,
                clubList: clubData,
                nationsList: nations,
                isLogin: req.session.passport === undefined ? false : true,
              });
              // res.json({
              //   totalPage: totalPage,
              //   players: players,
              // });
            });
            // res.json(players);
          })
          .catch((err) => {
            console.log(err);
            next();
          });
      })
      .catch((err) => {
        console.log(err);
        next();
      });
  }
  create(req, res, next) {
    Nations.find({})
      .then((nations) => {
        if (nations.length === 0) {
          req.flash(
            "error_msg",
            "Please input data of nations in Database first!!!"
          );
          return res.redirect("/players");
        }
      })
      .catch((err) => {
        req.flash("error_msg", "Server Error");
        return res.redirect("/players");
      });
    var data = {
      name: req.body.name,
      image:
        req.file === undefined
          ? ""
          : `/images/Players/${req.file.originalname}`,
      career: req.body.career,
      position: req.body.position,
      goals: req.body.goals,
      nation: req.body.nation,
      isCaptain: req.body.isCaptain === undefined ? false : true,
    };
    console.log("data: ", data);
    const player = new Players(data);
    Players.find({ name: player.name }).then((playerCheck) => {
      if (playerCheck.length > 0) {
        req.flash("error_msg", "Duplicate player name!");
        res.redirect("/players");
      } else {
        console.log(player);
        player
          .save()
          .then(() => res.redirect("/players"))
          .catch(next);
      }
    });
  }
  playerDetail(req, res, next) {
    const playerId = req.params.playerId;
    Nations.find({})
      .then((nations) => {
        Players.findById(playerId)
          .populate("nation", "name")
          .then((player) => {
            res.render("playerDetail", {
              title: "The detail of Player",
              player: player,
              positionList: postitionData,
              clubList: clubData,
              nationsList: nations,
              isLogin: req.session.passport === undefined ? false : true,
            });
          })
          .catch(next);
      })
      .catch(next);
  }
  formEdit(req, res, next) {
    const playerId = req.params.playerId;
    Nations.find({})
      .then((nations) => {
        Players.findById(playerId)
          .then((player) => {
            res.render("editPlayer", {
              title: "The detail of Player",
              player: player,
              positionList: postitionData,
              clubList: clubData,
              nationsList: nations,
              isLogin: req.session.passport === undefined ? false : true,
            });
          })
          .catch(next);
      })
      .catch(next);
  }
  edit(req, res, next) {
    var data;
    if (!req.file) {
      data = {
        name: req.body.name,
        career: req.body.career,
        position: req.body.position,
        goals: req.body.goals,
        nation: req.body.nation,
        isCaptain: req.body.isCaptain === undefined ? false : true,
      };
    } else {
      data = {
        name: req.body.name,
        image: `/images/Players/${req.file.originalname}`,
        career: req.body.career,
        position: req.body.position,
        goals: req.body.goals,
        nation: req.body.nation,
        isCaptain: req.body.isCaptain === undefined ? false : true,
      };
    }
    Players.updateOne({ _id: req.params.playerId }, data)
      .then(() => {
        res.redirect("/players");
      })
      .catch((err) => {
        console.log("error update: ", err);
        req.flash("error_msg", "Duplicate player name!");
        res.redirect(`/players/edit/${req.params.playerId}`);
      });
  }
  delete(req, res, next) {
    Players.findByIdAndDelete({ _id: req.params.playerId })
      .then(() => res.redirect("/players"))
      .catch(next);
  }

  search = async (req, res, next) => {
    let payload = req.body.payload.trim();
    let searchResult = await Players.find({
      name: { $regex: new RegExp("^" + payload + ".*", "i") },
    }).populate("nation", ["name", "description"]);
    // search = search.slice(0, 10);
    res.send({ payload: searchResult });
  };

  filter = async (req, res, next) => {
    const { goals, career, position, nation, isCaptain } = req.body;
    const query = {};

    if (goals) query.goals = { $gte: goals };
    if (career) query.career = career;
    if (position) query.position = position;
    if (nation) {
      const foundNation = await Nations.findOne({ name: nation });
      if (foundNation) {
        query.nation = foundNation._id;
      }
    }
    if (isCaptain) query.isCaptain = true;

    console.log("query", query);
    Players.find(query)
      .populate("nation")
      .then((players) => {
        res.json(players);
      })
      .catch((error) => {
        res.status(500).json({ message: error.message });
      });
  };
}
module.exports = new PlayerController();
