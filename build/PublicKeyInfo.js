"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _common = require("./common");

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

var _ECPublicKey = require("./ECPublicKey");

var _ECPublicKey2 = _interopRequireDefault(_ECPublicKey);

var _RSAPublicKey = require("./RSAPublicKey");

var _RSAPublicKey2 = _interopRequireDefault(_RSAPublicKey);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var PublicKeyInfo = function () {
	//**********************************************************************************
	/**
  * Constructor for PublicKeyInfo class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function PublicKeyInfo() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, PublicKeyInfo);

		//region Internal properties of the object
		/**
   * @type {AlgorithmIdentifier}
   * @description Algorithm identifier
   */
		this.algorithm = (0, _pvutils.getParametersValue)(parameters, "algorithm", PublicKeyInfo.defaultValues("algorithm"));
		/**
   * @type {BitString}
   * @description Subject public key value
   */
		this.subjectPublicKey = (0, _pvutils.getParametersValue)(parameters, "subjectPublicKey", PublicKeyInfo.defaultValues("subjectPublicKey"));

		if ("parsedKey" in parameters)
			/**
    * @type {ECPublicKey|RSAPublicKey}
    * @description Parsed public key value
    */
			this.parsedKey = (0, _pvutils.getParametersValue)(parameters, "parsedKey", PublicKeyInfo.defaultValues("parsedKey"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if ("json" in parameters) this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(PublicKeyInfo, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, PublicKeyInfo.schema({
				names: {
					algorithm: {
						names: {
							blockName: "algorithm"
						}
					},
					subjectPublicKey: "subjectPublicKey"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for PUBLIC_KEY_INFO");
			//endregion

			//region Get internal properties from parsed schema
			this.algorithm = new _AlgorithmIdentifier2.default({ schema: asn1.result.algorithm });
			this.subjectPublicKey = asn1.result.subjectPublicKey;

			switch (this.algorithm.algorithmId) {
				case "1.2.840.10045.2.1":
					// ECDSA
					if ("algorithmParams" in this.algorithm) {
						if (this.algorithm.algorithmParams instanceof asn1js.ObjectIdentifier) {
							this.parsedKey = new _ECPublicKey2.default({
								namedCurve: this.algorithm.algorithmParams.valueBlock.toString(),
								schema: this.subjectPublicKey.valueBlock.valueHex
							});
						}
					}
					break;
				case "1.2.840.113549.1.1.1":
					// RSA
					{
						var publicKeyASN1 = asn1js.fromBER(this.subjectPublicKey.valueBlock.valueHex);
						if (publicKeyASN1.offset !== -1) this.parsedKey = new _RSAPublicKey2.default({ schema: publicKeyASN1.result });
					}
					break;
				default:
			}
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: [this.algorithm.toSchema(), this.subjectPublicKey]
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Convertion for the class to JSON object
   * @returns {Object}
   */

	}, {
		key: "toJSON",
		value: function toJSON() {
			//region Return common value in case we do not have enough info fo making JWK
			if ("parsedKey" in this === false) {
				return {
					algorithm: this.algorithm.toJSON(),
					subjectPublicKey: this.subjectPublicKey.toJSON()
				};
			}
			//endregion

			//region Making JWK
			var jwk = {};

			switch (this.algorithm.algorithmId) {
				case "1.2.840.10045.2.1":
					// ECDSA
					jwk.kty = "EC";
					break;
				case "1.2.840.113549.1.1.1":
					// RSA
					jwk.kty = "RSA";
					break;
				default:
			}

			var publicKeyJWK = this.parsedKey.toJSON();

			var _iteratorNormalCompletion = true;
			var _didIteratorError = false;
			var _iteratorError = undefined;

			try {
				for (var _iterator = Object.keys(publicKeyJWK)[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
					var key = _step.value;

					jwk[key] = publicKeyJWK[key];
				}
			} catch (err) {
				_didIteratorError = true;
				_iteratorError = err;
			} finally {
				try {
					if (!_iteratorNormalCompletion && _iterator.return) {
						_iterator.return();
					}
				} finally {
					if (_didIteratorError) {
						throw _iteratorError;
					}
				}
			}

			return jwk;
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert JSON value into current object
   * @param {Object} json
   */

	}, {
		key: "fromJSON",
		value: function fromJSON(json) {
			if ("kty" in json) {
				switch (json.kty.toUpperCase()) {
					case "EC":
						this.parsedKey = new _ECPublicKey2.default({ json: json });

						this.algorithm = new _AlgorithmIdentifier2.default({
							algorithmId: "1.2.840.10045.2.1",
							algorithmParams: new asn1js.ObjectIdentifier({ value: this.parsedKey.namedCurve })
						});
						break;
					case "RSA":
						this.parsedKey = new _RSAPublicKey2.default({ json: json });

						this.algorithm = new _AlgorithmIdentifier2.default({
							algorithmId: "1.2.840.113549.1.1.1",
							algorithmParams: new asn1js.Null()
						});
						break;
					default:
						throw new Error("Invalid value for \"kty\" parameter: " + json.kty);
				}

				this.subjectPublicKey = new asn1js.BitString({ valueHex: this.parsedKey.toSchema().toBER(false) });
			}
		}
		//**********************************************************************************

	}, {
		key: "importKey",
		value: function importKey(publicKey) {
			//region Initial variables
			var sequence = Promise.resolve();
			var _this = this;
			//endregion

			//region Initial check
			if (typeof publicKey === "undefined") return Promise.reject("Need to provide publicKey input parameter");
			//endregion

			//region Get a "crypto" extension
			var crypto = (0, _common.getCrypto)();
			if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
			//endregion

			//region Export public key
			sequence = sequence.then(function () {
				return crypto.exportKey("spki", publicKey);
			});
			//endregion

			//region Initialize internal variables by parsing exported value
			sequence = sequence.then(function (exportedKey) {
				var asn1 = asn1js.fromBER(exportedKey);
				try {
					_this.fromSchema(asn1.result);
				} catch (exception) {
					return Promise.reject("Error during initializing object from schema");
				}

				return undefined;
			}, function (error) {
				return Promise.reject("Error during exporting public key: " + error);
			});
			//endregion

			return sequence;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "algorithm":
					return new _AlgorithmIdentifier2.default();
				case "subjectPublicKey":
					return new asn1js.BitString();
				default:
					throw new Error("Invalid member name for PublicKeyInfo class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//SubjectPublicKeyInfo  ::=  Sequence  {
			//    algorithm            AlgorithmIdentifier,
			//    subjectPublicKey     BIT STRING  }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [algorithm]
    * @property {string} [subjectPublicKey]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [_AlgorithmIdentifier2.default.schema(names.algorithm || {}), new asn1js.BitString({ name: names.subjectPublicKey || "" })]
			});
		}
	}]);

	return PublicKeyInfo;
}();
//**************************************************************************************


exports.default = PublicKeyInfo;
//# sourceMappingURL=PublicKeyInfo.js.map